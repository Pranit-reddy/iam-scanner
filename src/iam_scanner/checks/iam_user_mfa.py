"""CIS 1.10: IAM users with a console password but no active MFA device."""

from __future__ import annotations

from iam_scanner.aws import ScanContext
from iam_scanner.models import Finding, Severity

# The root user has its own row in the credential report; root MFA is a different
# CIS control (1.5) and out of scope here.
_ROOT_ROW = "<root_account>"


def check(ctx: ScanContext) -> list[Finding]:
    findings = []
    for row in ctx.credential_report():
        if row["user"] == _ROOT_ROW:
            continue
        if row["password_enabled"] != "true" or row["mfa_active"] == "true":
            continue
        findings.append(
            Finding(
                check_id=__name__.rsplit(".", 1)[-1],
                resource_type="AWS::IAM::User",
                resource_id=row["arn"],
                region="global",
                severity=Severity.HIGH,
                title="IAM user has console access without MFA",
                description=(
                    f"User {row['user']} can sign in to the AWS console with a password, "
                    f"but has no active MFA device."
                ),
                cis_controls=["1.10"],
                evidence={
                    "user": row["user"],
                    "password_enabled": row["password_enabled"],
                    "password_last_used": row["password_last_used"],
                    "mfa_active": row["mfa_active"],
                },
            )
        )
    return findings
