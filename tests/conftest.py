import boto3
import pytest
from moto import mock_aws

from iam_scanner.aws import ScanContext

REGION = "us-east-1"


@pytest.fixture(autouse=True)
def aws_credentials(monkeypatch):
    """Fake credentials so nothing can ever reach a real AWS account."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.delenv("AWS_PROFILE", raising=False)


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
