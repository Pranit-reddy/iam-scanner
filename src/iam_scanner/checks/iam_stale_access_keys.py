"""CIS 1.12 / 1.14: active access keys that are unused or overdue for rotation."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from iam_scanner.aws import ScanContext, parse_report_timestamp
from iam_scanner.models import Finding, Severity

_ROOT_ROW = "<root_account>"
_KEY_SLOTS = (1, 2)  # the credential report has columns for at most two keys per user


def check(ctx: ScanContext) -> list[Finding]:
    unused_limit = timedelta(days=ctx.thresholds.key_unused_days)
    age_limit = timedelta(days=ctx.thresholds.key_max_age_days)
    findings = []
    for row in ctx.credential_report():
        if row["user"] == _ROOT_ROW:
            continue
        for slot in _KEY_SLOTS:
            if row[f"access_key_{slot}_active"] != "true":
                continue
            created = parse_report_timestamp(row[f"access_key_{slot}_last_rotated"])
            if created is None:
                continue
            last_used = parse_report_timestamp(row[f"access_key_{slot}_last_used_date"])
            age = ctx.now - created
            # CIS 1.12: a key that was never used counts as unused since it was created.
            unused = ctx.now - (last_used or created)
            controls = []
            if unused >= unused_limit:  # "unused for 45 days or greater"
                controls.append("1.12")
            if age > age_limit:  # "rotated every 90 days or less"
                controls.append("1.14")
            if controls:
                findings.append(_finding(ctx, row, slot, created, last_used, age, unused, controls))
    return findings


def _finding(
    ctx: ScanContext,
    row: dict[str, str],
    slot: int,
    created: datetime,
    last_used: datetime | None,
    age: timedelta,
    unused: timedelta,
    controls: list[str],
) -> Finding:
    user = row["user"]
    key_id = _access_key_id(ctx, user, created)
    problems = []
    if "1.12" in controls:
        problems.append("never used" if last_used is None else f"unused for {unused.days} days")
    if "1.14" in controls:
        problems.append(f"not rotated in {age.days} days")
    usage = "has never been used" if last_used is None else f"was last used {unused.days} days ago"
    return Finding(
        check_id=__name__.rsplit(".", 1)[-1],
        resource_type="AWS::IAM::User",
        resource_id=row["arn"],
        region="global",
        severity=Severity.MEDIUM,
        title=f"Access key {' and '.join(problems)}",
        description=(
            f"Access key {key_id or f'#{slot}'} on user {user} is active, "
            f"{usage} "
            f"and was created {age.days} days ago (limits: unused ≥ "
            f"{ctx.thresholds.key_unused_days} days, age > {ctx.thresholds.key_max_age_days} days)."
        ),
        cis_controls=controls,
        evidence={
            "user": user,
            "access_key_id": key_id,
            "key_slot": slot,
            "created": created.isoformat(),
            "last_used": last_used.isoformat() if last_used else None,
            "age_days": age.days,
            "unused_days": unused.days,
            "thresholds": {
                "key_unused_days": ctx.thresholds.key_unused_days,
                "key_max_age_days": ctx.thresholds.key_max_age_days,
            },
        },
    )


def _access_key_id(ctx: ScanContext, user: str, created: datetime) -> str | None:
    """The credential report omits key IDs; find the key whose creation time matches."""
    keys: list[dict[str, Any]] = ctx.client("iam").list_access_keys(UserName=user)[
        "AccessKeyMetadata"
    ]
    for key in keys:
        if key["CreateDate"].replace(microsecond=0) == created:
            return key["AccessKeyId"]
    return None
