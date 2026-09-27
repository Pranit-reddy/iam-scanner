import json

import pytest

from iam_scanner.checks import s3_public_bucket
from iam_scanner.checks.s3_public_bucket import check
from iam_scanner.models import Severity

ACCOUNT = "123456789012"  # moto's default account
ALL_OFF = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}
ALL_ON = {k: True for k in ALL_OFF}


def _policy(bucket, principal="*", condition=None):
    stmt = {
        "Effect": "Allow",
        "Principal": principal,
        "Action": "s3:GetObject",
        "Resource": f"arn:aws:s3:::{bucket}/*",
    }
    if condition:
        stmt["Condition"] = condition
    return json.dumps({"Version": "2012-10-17", "Statement": [stmt]})


def _bucket(s3, name, policy=None, block=ALL_OFF):
    s3.create_bucket(Bucket=name)
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=ALL_OFF)
    if policy:
        s3.put_bucket_policy(Bucket=name, Policy=policy)
    # Applied after the policy, as BlockPublicPolicy would reject a public policy.
    s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=block)


@pytest.mark.parametrize("principal", ["*", {"AWS": "*"}, {"AWS": ["*"]}])
def test_flags_public_policy_with_block_public_access_off(ctx, principal):
    _bucket(ctx.client("s3"), "public-bucket", policy=_policy("public-bucket", principal))

    findings = check(ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == "arn:aws:s3:::public-bucket"
    assert f.resource_type == "AWS::S3::Bucket"
    assert f.region == "us-east-1"
    assert f.severity is Severity.CRITICAL
    assert f.cis_controls == ["2.1.4"]
    assert f.evidence["bucket_block_public_access"] == ALL_OFF
    assert f.evidence["public_statements"][0]["Action"] == "s3:GetObject"


def test_ignores_public_policy_when_bucket_block_public_access_on(ctx):
    _bucket(ctx.client("s3"), "blocked", policy=_policy("blocked"), block=ALL_ON)
    assert check(ctx) == []


def test_ignores_public_policy_when_account_block_public_access_on(ctx):
    _bucket(ctx.client("s3"), "acct-blocked", policy=_policy("acct-blocked"))
    ctx.client("s3control").put_public_access_block(
        AccountId=ACCOUNT, PublicAccessBlockConfiguration=ALL_ON
    )
    assert check(ctx) == []


def test_ignores_bucket_without_policy(ctx):
    _bucket(ctx.client("s3"), "no-policy")
    assert check(ctx) == []


def test_ignores_policy_scoped_to_specific_account(ctx):
    principal = {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}
    _bucket(ctx.client("s3"), "private", policy=_policy("private", principal))
    assert check(ctx) == []


def test_ignores_wildcard_principal_restricted_by_condition(ctx):
    condition = {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}
    _bucket(ctx.client("s3"), "org-only", policy=_policy("org-only", condition=condition))
    assert check(ctx) == []


# moto accepts GetBucketPolicyStatus but returns no IsPublic, so the tests above get
# aws_verdict=None. These stub AWS's verdict to test the cross-check.


def _stub_aws_verdict(monkeypatch, verdict):
    monkeypatch.setattr(s3_public_bucket, "_policy_status_is_public", lambda s3, bucket: verdict)


def test_aws_public_overrides_parser_condition_and_notes_discrepancy(ctx, monkeypatch):
    # aws:SecureTransport only requires HTTPS; anyone can still read. Our parser treats
    # any Condition as narrowing, AWS's evaluation knows better.
    condition = {"Bool": {"aws:SecureTransport": "true"}}
    _bucket(ctx.client("s3"), "https-only", policy=_policy("https-only", condition=condition))
    _stub_aws_verdict(monkeypatch, True)

    [f] = check(ctx)

    assert f.evidence["parser_is_public"] is False
    assert f.evidence["policy_status_is_public"] is True
    assert "IsPublic=true" in f.evidence["verdict_discrepancy"]
    assert f.evidence["public_statements"][0]["Condition"] == condition


def test_parser_public_but_aws_private_still_flagged_with_discrepancy(ctx, monkeypatch):
    _bucket(ctx.client("s3"), "aws-says-private", policy=_policy("aws-says-private"))
    _stub_aws_verdict(monkeypatch, False)

    [f] = check(ctx)

    assert f.evidence["parser_is_public"] is True
    assert "IsPublic=false" in f.evidence["verdict_discrepancy"]


def test_both_private_not_flagged(ctx, monkeypatch):
    condition = {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}
    _bucket(ctx.client("s3"), "org-only-2", policy=_policy("org-only-2", condition=condition))
    _stub_aws_verdict(monkeypatch, False)
    assert check(ctx) == []


def test_agreeing_verdicts_have_no_discrepancy(ctx, monkeypatch):
    _bucket(ctx.client("s3"), "agree", policy=_policy("agree"))
    _stub_aws_verdict(monkeypatch, True)
    [f] = check(ctx)
    assert f.evidence["verdict_discrepancy"] is None


def test_no_aws_verdict_recorded_as_none(ctx):
    _bucket(ctx.client("s3"), "fallback", policy=_policy("fallback"))
    [f] = check(ctx)
    assert f.evidence["policy_status_is_public"] is None
    assert f.evidence["verdict_discrepancy"] is None
