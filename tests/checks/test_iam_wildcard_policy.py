import json

from iam_scanner.checks.iam_wildcard_policy import check
from iam_scanner.models import Severity

WILDCARD = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
SCOPED = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}],
}
TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _create_policy(iam, name, document):
    return iam.create_policy(PolicyName=name, PolicyDocument=json.dumps(document))["Policy"]["Arn"]


def test_flags_wildcard_policy_attached_to_group(ctx):
    iam = ctx.client("iam")
    arn = _create_policy(iam, "wildcard", WILDCARD)
    iam.create_group(GroupName="admins")
    iam.attach_group_policy(GroupName="admins", PolicyArn=arn)

    findings = check(ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == arn
    assert f.resource_type == "AWS::IAM::ManagedPolicy"
    assert f.region == "global"
    assert f.severity is Severity.CRITICAL
    assert f.cis_controls == ["1.16"]
    assert f.evidence["attached_to"] == ["group/admins"]


def test_flags_list_form_wildcard_attached_to_user_and_role(ctx):
    iam = ctx.client("iam")
    doc = {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": ["*"], "Resource": ["*"]},
    }
    arn = _create_policy(iam, "wildcard-list", doc)
    iam.create_user(UserName="alice")
    iam.attach_user_policy(UserName="alice", PolicyArn=arn)
    iam.create_role(RoleName="ops", AssumeRolePolicyDocument=json.dumps(TRUST))
    iam.attach_role_policy(RoleName="ops", PolicyArn=arn)

    findings = check(ctx)

    assert len(findings) == 1
    assert findings[0].evidence["attached_to"] == ["role/ops", "user/alice"]


def test_ignores_unattached_wildcard_policy(ctx):
    _create_policy(ctx.client("iam"), "wildcard-unused", WILDCARD)
    assert check(ctx) == []


def test_ignores_attached_scoped_policy(ctx):
    iam = ctx.client("iam")
    arn = _create_policy(iam, "scoped", SCOPED)
    iam.create_group(GroupName="readers")
    iam.attach_group_policy(GroupName="readers", PolicyArn=arn)
    assert check(ctx) == []
