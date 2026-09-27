"""CIS 2.1.4: S3 buckets made public by a bucket policy that Block Public Access doesn't stop."""

from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from iam_scanner.aws import ScanContext
from iam_scanner.models import Finding, Severity

_BPA_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
_NO_BPA = "NoSuchPublicAccessBlockConfiguration"


def check(ctx: ScanContext) -> list[Finding]:
    s3 = ctx.client("s3")
    account_bpa = _account_block_public_access(ctx)
    findings = []
    for bucket in s3.list_buckets()["Buckets"]:
        name = bucket["Name"]
        region = _bucket_region(s3, name)
        regional = ctx.client("s3", region)
        bucket_bpa = _bucket_block_public_access(regional, name)
        # RestrictPublicBuckets (bucket or account) is what blocks access via a public policy;
        # BlockPublicPolicy only stops a new public policy from being saved.
        if bucket_bpa["RestrictPublicBuckets"] or account_bpa["RestrictPublicBuckets"]:
            continue
        policy = _bucket_policy(regional, name)
        if policy is None:
            continue
        # Two opinions: our parser, and AWS's own evaluation (which understands conditions).
        # Public if either says so; a disagreement is recorded in the evidence.
        wildcard = _wildcard_statements(policy)
        parser_verdict = _any_unconditional(wildcard)
        aws_verdict = _policy_status_is_public(regional, name)
        if not (parser_verdict or aws_verdict):
            continue
        findings.append(
            Finding(
                check_id=__name__.rsplit(".", 1)[-1],
                resource_type="AWS::S3::Bucket",
                resource_id=f"arn:aws:s3:::{name}",
                region=region,
                severity=Severity.CRITICAL,
                title="S3 bucket is publicly accessible via its bucket policy",
                description=(
                    f"Bucket {name} has a bucket policy that allows anyone "
                    f'(Principal "*") access, and Block Public Access does not restrict it '
                    f"at the bucket or account level."
                ),
                cis_controls=["2.1.4"],
                evidence={
                    "bucket_block_public_access": bucket_bpa,
                    "account_block_public_access": account_bpa,
                    "parser_is_public": parser_verdict,
                    "policy_status_is_public": aws_verdict,
                    "verdict_discrepancy": _discrepancy(parser_verdict, aws_verdict),
                    "public_statements": wildcard,
                },
            )
        )
    return findings


def _discrepancy(parser_verdict: bool, aws_verdict: bool | None) -> str | None:
    """Explain a disagreement between our parser and GetBucketPolicyStatus, if any."""
    if aws_verdict is None or aws_verdict == parser_verdict:
        return None
    if aws_verdict:
        return (
            "GetBucketPolicyStatus reports IsPublic=true, but the scanner's policy parser "
            "treated every wildcard statement as narrowed by a Condition."
        )
    return (
        "The scanner's policy parser found an unconditional wildcard statement, but "
        "GetBucketPolicyStatus reports IsPublic=false. Flagged as public to be safe."
    )


def _account_block_public_access(ctx: ScanContext) -> dict[str, bool]:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    try:
        config = ctx.client("s3control").get_public_access_block(AccountId=account_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == _NO_BPA:
            return dict.fromkeys(_BPA_KEYS, False)
        raise
    return _normalise_bpa(config["PublicAccessBlockConfiguration"])


def _bucket_block_public_access(s3: Any, bucket: str) -> dict[str, bool]:
    try:
        config = s3.get_public_access_block(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == _NO_BPA:
            return dict.fromkeys(_BPA_KEYS, False)
        raise
    return _normalise_bpa(config["PublicAccessBlockConfiguration"])


def _normalise_bpa(config: dict[str, Any]) -> dict[str, bool]:
    return {k: bool(config.get(k, False)) for k in _BPA_KEYS}


def _bucket_region(s3: Any, bucket: str) -> str:
    location = s3.get_bucket_location(Bucket=bucket)["LocationConstraint"]
    # us-east-1 buckets report no location; "EU" is the legacy name for eu-west-1.
    return {None: "us-east-1", "EU": "eu-west-1"}.get(location, location)


def _bucket_policy(s3: Any, bucket: str) -> dict[str, Any] | None:
    try:
        return json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucketPolicy":
            return None
        raise


def _policy_status_is_public(s3: Any, bucket: str) -> bool | None:
    """AWS's verdict from GetBucketPolicyStatus, or None if it gives none."""
    return s3.get_bucket_policy_status(Bucket=bucket).get("PolicyStatus", {}).get("IsPublic")


def _wildcard_statements(policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Allow statements whose principal is everyone (with or without a Condition)."""
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    return [
        s for s in statements if s.get("Effect") == "Allow" and _is_everyone(s.get("Principal"))
    ]


def _any_unconditional(statements: list[dict[str, Any]]) -> bool:
    """Fallback rule: a wildcard statement with no Condition narrowing it is public."""
    return any("Condition" not in s for s in statements)


def _is_everyone(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        return aws == "*" or (isinstance(aws, list) and "*" in aws)
    return False
