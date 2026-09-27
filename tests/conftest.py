import boto3
import botocore.httpsession
import pytest
from moto import mock_aws

from iam_scanner.aws import ScanContext

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch, tmp_path):
    """Fake credentials, and no other credential source to fall back to."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    # Never read the developer's ~/.aws files or the EC2/ECS metadata endpoints.
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "no-aws-credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    for var in (
        "AWS_PROFILE",
        "AWS_ROLE_ARN",
        "AWS_WEB_IDENTITY_TOKEN_FILE",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture(autouse=True)
def block_real_aws_requests(monkeypatch):
    """Fail loudly if any request escapes moto.

    moto answers requests before botocore's HTTP layer sends them, so this only trips
    for a call made outside `mock_aws()`, e.g. a test that forgot the `ctx` fixture.
    """

    def refuse(self, request):
        raise RuntimeError(f"Test tried to reach real AWS: {request.method} {request.url}")

    monkeypatch.setattr(botocore.httpsession.URLLib3Session, "send", refuse)


@pytest.fixture
def mocked_aws():
    with mock_aws():
        yield


@pytest.fixture
def ctx(mocked_aws):
    return ScanContext(
        session=boto3.Session(region_name=REGION),
        regions=[REGION],
        report_poll_interval=0,
    )
