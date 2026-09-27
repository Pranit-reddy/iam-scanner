"""CIS 1.5: MFA enabled for the root user.

Decided by GetAccountSummary's AccountMFAEnabled (the CIS audit command), which is real
time. The credential report's <root_account> row is only supporting evidence: AWS
reuses a report for up to 4 hours, so it can still show MFA off after root MFA is set up.
"""

from __future__ import annotations

from iam_scanner.aws import ScanContext
from iam_scanner.models import Finding, Severity

_ROOT_ROW = "<root_account>"


def check(ctx: ScanContext) -> list[Finding]:
    if _account_mfa_enabled(ctx):
        return []
    root = next((r for r in ctx.credential_report() if r["user"] == _ROOT_ROW), {})
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    return [
        Finding(
            check_id=__name__.rsplit(".", 1)[-1],
            resource_type="AWS::IAM::RootUser",
            resource_id=root.get("arn", f"arn:aws:iam::{account_id}:root"),
            region="global",
            severity=Severity.CRITICAL,
            title="Root user does not have MFA enabled",
            description=(
                "The account's root user has no active MFA device. Anyone with the root "
                "email address and password has unrestricted control of the account."
            ),
            cis_controls=["1.5"],
            evidence={
                "account_mfa_enabled": False,
                "credential_report_mfa_active": root.get("mfa_active"),
                "password_last_used": root.get("password_last_used"),
            },
        )
    ]


def _account_mfa_enabled(ctx: ScanContext) -> bool:
    summary = ctx.client("iam").get_account_summary()["SummaryMap"]
    return summary.get("AccountMFAEnabled") == 1
