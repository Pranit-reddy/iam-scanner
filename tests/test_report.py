"""Golden-file test for the Markdown report.

If you change the report format on purpose, regenerate the fixture and review the diff:
    UPDATE_GOLDEN=1 pytest tests/test_report.py
"""

import os
from datetime import UTC, datetime
from pathlib import Path

from iam_scanner.models import CheckError, Finding, ScanResult, Severity
from iam_scanner.report.markdown import render_markdown

GOLDEN = Path(__file__).parent / "fixtures" / "expected_report.md"
ACCOUNT = "123456789012"


def _sample_result() -> ScanResult:
    # Deliberately out of severity order, to prove the report sorts them.
    return ScanResult(
        findings=[
            Finding(
                check_id="iam_stale_access_keys",
                resource_type="AWS::IAM::User",
                resource_id=f"arn:aws:iam::{ACCOUNT}:user/sandbox-stale-key-user",
                region="global",
                severity=Severity.MEDIUM,
                title="Access key unused for 120 days and not rotated in 200 days",
                description=(
                    "Access key AKIAEXAMPLE1 on user sandbox-stale-key-user is active, was "
                    "last used 120 days ago and was created 200 days ago."
                ),
                cis_controls=["1.12", "1.14"],
                evidence={
                    "access_key_id": "AKIAEXAMPLE1",
                    "created": "2026-03-10T00:00:00+00:00",
                    "last_used": "2026-05-29T00:00:00+00:00",
                    "status": "Active",
                },
            ),
            Finding(
                check_id="iam_wildcard_policy",
                resource_type="AWS::IAM::ManagedPolicy",
                resource_id=f"arn:aws:iam::{ACCOUNT}:policy/sandbox-wildcard-policy",
                region="global",
                severity=Severity.CRITICAL,
                title="Customer-managed policy grants full *:* admin access",
                description=(
                    'Policy sandbox-wildcard-policy allows "Action": "*" on "Resource": "*" '
                    "and is attached to 1 principal."
                ),
                cis_controls=["1.16"],
                evidence={
                    "attached_to": ["role/sandbox-admin-role"],
                    "statement": {"Action": "*", "Effect": "Allow", "Resource": "*"},
                },
            ),
            Finding(
                check_id="ec2_open_security_group",
                resource_type="AWS::EC2::SecurityGroup",
                resource_id="sg-0123456789abcdef0",
                region="us-east-1",
                severity=Severity.HIGH,
                title="Security group allows SSH (22) from 0.0.0.0/0",
                description=(
                    "Security group sandbox-open-sg allows inbound TCP 22 from anywhere on "
                    "the internet."
                ),
                cis_controls=["5.2"],
                evidence={"cidr": "0.0.0.0/0", "from_port": 22, "protocol": "tcp", "to_port": 22},
            ),
        ],
        passed=["iam_user_mfa"],
        errors=[
            CheckError(
                check_id="s3_public_bucket",
                message=(
                    "An error occurred (AccessDenied) when calling the ListBuckets operation: "
                    "Access Denied"
                ),
            )
        ],
    )


def _render() -> str:
    return render_markdown(
        _sample_result(),
        account_id=ACCOUNT,
        regions=["us-east-1"],
        generated_at=datetime(2026, 9, 26, 12, 0, 0, tzinfo=UTC),
    )


def test_report_matches_golden_file():
    actual = _render()
    if os.environ.get("UPDATE_GOLDEN"):
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(actual)
    assert actual == GOLDEN.read_text()


def test_empty_scan_report():
    report = render_markdown(
        ScanResult(passed=["iam_user_mfa"]),
        account_id=ACCOUNT,
        regions=["us-east-1"],
        generated_at=datetime(2026, 9, 26, tzinfo=UTC),
    )
    assert "No findings." in report
    assert "## Details" not in report
