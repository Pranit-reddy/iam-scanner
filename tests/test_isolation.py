"""Guards that the test suite can never talk to real AWS (see tests/conftest.py)."""

import boto3
import pytest


def test_request_outside_moto_is_blocked():
    with pytest.raises(RuntimeError, match="Test tried to reach real AWS"):
        boto3.client("sts", region_name="us-east-1").get_caller_identity()


def test_no_profile_or_config_file_fallback():
    session = boto3.Session()
    assert session.profile_name == "default"
    assert session.available_profiles == []  # ~/.aws files are redirected to missing paths
    assert session.get_credentials().access_key == "testing"
