"""Root MFA (CIS 1.5).

moto's GetAccountSummary always reports AccountMFAEnabled=0, so the "no MFA" case runs on
plain moto. Root MFA can't be enabled in moto, so the "has MFA" cases stub that one lookup.
moto's credential report also has no <root_account> row; tests that need one add it.
"""

import pytest

from iam_scanner.checks import iam_root_mfa
from iam_scanner.checks.iam_root_mfa import check
from iam_scanner.models import Severity


def _root_row(mfa_active):
    return {
        "user": "<root_account>",
        "arn": "arn:aws:iam::123456789012:root",
        "password_enabled": "not_supported",
        "password_last_used": "2026-09-01T00:00:00+00:00",
        "mfa_active": mfa_active,
    }


@pytest.fixture
def root_row(ctx, monkeypatch):
    def install(mfa_active):
        rows = [_root_row(mfa_active), *ctx.credential_report()]
        monkeypatch.setattr(ctx, "credential_report", lambda: rows)

    return install


@pytest.fixture
def root_mfa_enabled(monkeypatch):
    monkeypatch.setattr(iam_root_mfa, "_account_mfa_enabled", lambda ctx: True)


def test_flags_root_without_mfa(ctx, root_row):
    root_row("false")

    [f] = check(ctx)

    assert f.resource_id == "arn:aws:iam::123456789012:root"
    assert f.resource_type == "AWS::IAM::RootUser"
    assert f.severity is Severity.CRITICAL
    assert f.cis_controls == ["1.5"]
    assert f.evidence["account_mfa_enabled"] is False
    assert f.evidence["credential_report_mfa_active"] == "false"


def test_flags_root_without_mfa_even_without_report_row(ctx):
    # Plain moto: AccountMFAEnabled=0 and no root row in the report.
    [f] = check(ctx)
    assert f.resource_id == "arn:aws:iam::123456789012:root"
    assert f.evidence["credential_report_mfa_active"] is None


def test_passes_when_root_has_mfa(ctx, root_row, root_mfa_enabled):
    root_row("true")
    assert check(ctx) == []


def test_stale_credential_report_does_not_cause_false_positive(ctx, root_row, root_mfa_enabled):
    # Regression: root MFA was just enabled, but AWS is still serving a credential report
    # (up to 4 hours old) that says mfa_active=false. AccountMFAEnabled is authoritative.
    root_row("false")
    assert check(ctx) == []
