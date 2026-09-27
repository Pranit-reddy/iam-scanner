"""Check registry and runner."""

from __future__ import annotations

from collections.abc import Callable, Iterable

from botocore.exceptions import BotoCoreError, ClientError

from iam_scanner.aws import ScanContext
from iam_scanner.controls import CONTROLS
from iam_scanner.models import CheckError, Finding, ScanResult

Check = Callable[[ScanContext], list[Finding]]

from iam_scanner.checks import (  # noqa: E402
    ec2_open_security_group,
    iam_root_mfa,
    iam_stale_access_keys,
    iam_user_mfa,
    iam_wildcard_policy,
    s3_public_bucket,
)

# Checks are appended here as they are implemented.
CHECKS: list[Check] = [
    iam_wildcard_policy.check,
    ec2_open_security_group.check,
    s3_public_bucket.check,
    iam_user_mfa.check,
    iam_root_mfa.check,
    iam_stale_access_keys.check,
]


def check_id(check: Check) -> str:
    """A check's ID is its module name, e.g. `iam_wildcard_policy`."""
    return check.__module__.rsplit(".", 1)[-1]


def run_all(
    ctx: ScanContext,
    checks: Iterable[Check] | None = None,
    only: set[str] | None = None,
) -> ScanResult:
    """Run each check and collect its findings.

    An AWS error in one check is recorded as a CheckError; the other checks still run.
    """
    result = ScanResult()
    for check in CHECKS if checks is None else checks:
        cid = check_id(check)
        if only is not None and cid not in only:
            continue
        try:
            findings = check(ctx)
        except (ClientError, BotoCoreError) as exc:
            result.errors.append(CheckError(check_id=cid, message=str(exc)))
            continue
        for f in findings:
            unknown = [c for c in f.cis_controls if c not in CONTROLS]
            if unknown:
                raise ValueError(f"{cid} reported unknown CIS control(s): {unknown}")
        if findings:
            result.findings.extend(findings)
        else:
            result.passed.append(cid)
    return result
