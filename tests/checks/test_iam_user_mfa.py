from iam_scanner.checks.iam_user_mfa import check
from iam_scanner.models import Severity


def _console_user(iam, name):
    iam.create_user(UserName=name)
    iam.create_login_profile(UserName=name, Password="Sandbox-Passw0rd!")


def _flagged_users(ctx):
    return [f.evidence["user"] for f in check(ctx)]


def test_flags_console_user_without_mfa(ctx):
    iam = ctx.client("iam")
    _console_user(iam, "no-mfa")

    findings = check(ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.resource_id == "arn:aws:iam::123456789012:user/no-mfa"
    assert f.resource_type == "AWS::IAM::User"
    assert f.region == "global"
    assert f.severity is Severity.HIGH
    assert f.cis_controls == ["1.10"]
    assert f.evidence["password_enabled"] == "true"
    assert f.evidence["mfa_active"] == "false"


def test_ignores_console_user_with_active_mfa(ctx):
    iam = ctx.client("iam")
    _console_user(iam, "with-mfa")
    serial = iam.create_virtual_mfa_device(VirtualMFADeviceName="with-mfa")["VirtualMFADevice"][
        "SerialNumber"
    ]
    iam.enable_mfa_device(
        UserName="with-mfa",
        SerialNumber=serial,
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )
    assert _flagged_users(ctx) == []


def test_ignores_programmatic_only_user(ctx):
    # Like the sandbox's stale-key user: an access key, but no console password.
    iam = ctx.client("iam")
    iam.create_user(UserName="api-only")
    iam.create_access_key(UserName="api-only")
    assert _flagged_users(ctx) == []


def test_ignores_user_without_any_credentials(ctx):
    ctx.client("iam").create_user(UserName="bare")
    assert _flagged_users(ctx) == []


def test_only_console_users_without_mfa_are_flagged(ctx):
    iam = ctx.client("iam")
    _console_user(iam, "no-mfa-1")
    _console_user(iam, "no-mfa-2")
    iam.create_user(UserName="api-only")
    iam.create_access_key(UserName="api-only")
    assert sorted(_flagged_users(ctx)) == ["no-mfa-1", "no-mfa-2"]
