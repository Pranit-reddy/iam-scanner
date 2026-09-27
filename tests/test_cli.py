import pytest

from iam_scanner.cli import EXIT_FINDINGS, EXIT_OK, main


def _run(tmp_path, *args):
    output = tmp_path / "scan.md"
    code = main(["--region", "us-east-1", "--output", str(output), *args])
    return code, output


def test_clean_scan_exits_zero_and_writes_report(mocked_aws, tmp_path, capsys):
    code, output = _run(tmp_path, "--checks", "iam_wildcard_policy,ec2_open_security_group")

    assert code == EXIT_OK
    assert "No findings." in output.read_text()
    assert capsys.readouterr().out.startswith("0 findings (0 critical, 0 high, 0 medium, 0 low)")


def test_critical_finding_exits_one(mocked_aws, tmp_path, capsys):
    # moto reports AccountMFAEnabled=0, so the root MFA check always fails there.
    code, output = _run(tmp_path, "--checks", "iam_root_mfa")

    assert code == EXIT_FINDINGS
    assert "Root user does not have MFA enabled" in output.read_text()
    assert "1 critical" in capsys.readouterr().out


def test_medium_only_findings_exit_zero(mocked_aws, tmp_path):
    import boto3

    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="k")
    iam.create_access_key(UserName="k")

    code, _ = _run(
        tmp_path,
        "--checks",
        "iam_stale_access_keys",
        "--key-unused-days",
        "0",
        "--key-max-age-days",
        "0",
    )

    assert code == EXIT_OK  # stale keys are Medium, which doesn't fail the build


def test_unknown_check_is_a_usage_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        _run(tmp_path, "--checks", "iam_wildcard_policy,not_a_check")
    assert exc.value.code == 2
    assert "not_a_check" in capsys.readouterr().err


def test_negative_threshold_rejected(tmp_path):
    with pytest.raises(SystemExit) as exc:
        _run(tmp_path, "--key-unused-days", "-1")
    assert exc.value.code == 2
