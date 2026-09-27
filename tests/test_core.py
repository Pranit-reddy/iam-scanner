import pytest
from botocore.exceptions import ClientError

from iam_scanner.aws import parse_report_timestamp
from iam_scanner.checks import run_all
from iam_scanner.controls import CONTROLS
from iam_scanner.models import Finding, ScanResult, Severity


def _finding(severity: Severity, resource_id: str = "r", controls=("1.16",)) -> Finding:
    return Finding(
        check_id="fake",
        resource_type="AWS::IAM::Policy",
        resource_id=resource_id,
        region="global",
        severity=severity,
        title="t",
        description="d",
        cis_controls=list(controls),
    )


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW
    assert Severity.CRITICAL.label == "Critical"


def test_sorted_findings_critical_first():
    result = ScanResult(findings=[_finding(Severity.LOW), _finding(Severity.CRITICAL)])
    assert [f.severity for f in result.sorted_findings()] == [Severity.CRITICAL, Severity.LOW]


def test_catalogue_has_all_planned_controls():
    assert set(CONTROLS) == {"1.5", "1.10", "1.12", "1.14", "1.16", "2.1.4", "5.2", "5.3"}
    for control in CONTROLS.values():
        assert control.title and control.rationale and control.remediation


def test_credential_report_is_cached(ctx):
    ctx.client("iam").create_user(UserName="alice")
    rows = ctx.credential_report()
    assert "alice" in {r["user"] for r in rows}
    assert {"password_enabled", "mfa_active", "access_key_1_last_used_date"} <= set(rows[0])
    ctx.client("iam").create_user(UserName="bob")
    assert ctx.credential_report() is rows  # not refetched within the same scan


def test_parse_report_timestamp():
    assert parse_report_timestamp("N/A") is None
    assert parse_report_timestamp("no_information") is None
    assert parse_report_timestamp("2026-01-02T03:04:05+00:00").year == 2026


def fake_ok(ctx):
    return []


def fake_vulnerable(ctx):
    return [_finding(Severity.HIGH)]


def fake_denied(ctx):
    raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "ListUsers")


def fake_bad_control(ctx):
    return [_finding(Severity.HIGH, controls=("9.99",))]


def test_run_all_collects_findings_passes_and_errors(ctx):
    result = run_all(ctx, checks=[fake_ok, fake_vulnerable, fake_denied])
    assert len(result.findings) == 1
    assert result.passed == ["test_core"]  # check_id is the module name
    assert len(result.errors) == 1 and "AccessDenied" in result.errors[0].message


def test_run_all_rejects_unknown_control(ctx):
    with pytest.raises(ValueError, match="9.99"):
        run_all(ctx, checks=[fake_bad_control])
