"""Stale access keys, tested against moto with fixed timestamps.

moto stamps new keys with the real current time, so each test backdates the key's
create_date / last_used on moto's backend objects (a supported moto pattern) and pins
ctx.now. Ages are therefore exact, and the real 45/90-day CIS thresholds are exercised.
"""

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest
from moto.iam.models import AccessKeyLastUsed, iam_backends

from iam_scanner.aws import Thresholds
from iam_scanner.checks.iam_stale_access_keys import check
from iam_scanner.models import Severity

ACCOUNT = "123456789012"
NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def pinned(ctx):
    ctx.now = NOW
    return ctx


def _key(ctx, user, created_days_ago, used_days_ago=None, active=True):
    """Create an access key for `user` with a backdated creation (and last-use) time."""
    iam = ctx.client("iam")
    if user not in {u["UserName"] for u in iam.list_users()["Users"]}:
        iam.create_user(UserName=user)
    key_id = iam.create_access_key(UserName=user)["AccessKey"]["AccessKeyId"]
    if not active:
        iam.update_access_key(UserName=user, AccessKeyId=key_id, Status="Inactive")
    key = iam_backends[ACCOUNT]["aws"].access_keys[key_id]
    key.create_date = NOW - timedelta(days=created_days_ago)
    if used_days_ago is not None:
        key.last_used = AccessKeyLastUsed(
            timestamp=NOW - timedelta(days=used_days_ago), service="s3", region="us-east-1"
        )
    return key_id


def _controls_by_key(ctx):
    return {f.evidence["access_key_id"]: f.cis_controls for f in check(ctx)}


def test_recently_used_young_key_not_flagged_at_defaults(pinned):
    _key(pinned, "active-user", created_days_ago=30, used_days_ago=10)
    assert check(pinned) == []


def test_never_used_100_day_old_key_flagged_for_both(pinned):
    key_id = _key(pinned, "stale-user", created_days_ago=100)

    [f] = check(pinned)

    assert f.cis_controls == ["1.12", "1.14"]
    assert f.severity is Severity.MEDIUM
    assert f.resource_type == "AWS::IAM::User"
    assert f.resource_id == f"arn:aws:iam::{ACCOUNT}:user/stale-user"
    assert f.region == "global"
    assert f.evidence["access_key_id"] == key_id
    assert f.evidence["last_used"] is None
    assert f.evidence["age_days"] == 100
    assert f.evidence["unused_days"] == 100  # never used: measured from creation


def test_unused_but_young_key_flagged_for_1_12_only(pinned):
    key_id = _key(pinned, "idle-user", created_days_ago=60, used_days_ago=50)
    assert _controls_by_key(pinned) == {key_id: ["1.12"]}


def test_used_but_old_key_flagged_for_1_14_only(pinned):
    key_id = _key(pinned, "busy-user", created_days_ago=100, used_days_ago=1)
    assert _controls_by_key(pinned) == {key_id: ["1.14"]}


def test_threshold_boundaries(pinned):
    # CIS 1.12 is "45 days or greater"; CIS 1.14 is "90 days or less" is fine.
    unused_45 = _key(pinned, "boundary-unused", created_days_ago=45)
    aged_90 = _key(pinned, "boundary-age", created_days_ago=90, used_days_ago=1)
    aged_91 = _key(pinned, "boundary-age-91", created_days_ago=91, used_days_ago=1)

    controls = _controls_by_key(pinned)

    assert controls[unused_45] == ["1.12"]
    assert aged_90 not in controls
    assert controls[aged_91] == ["1.14"]


def test_inactive_key_ignored(pinned):
    _key(pinned, "disabled-user", created_days_ago=400, active=False)
    assert check(pinned) == []


def test_both_key_slots_checked(pinned):
    fresh = _key(pinned, "two-keys", created_days_ago=5, used_days_ago=1)
    old = _key(pinned, "two-keys", created_days_ago=120, used_days_ago=100)
    assert _controls_by_key(pinned) == {old: ["1.12", "1.14"]}
    assert fresh


def test_zero_thresholds_flag_brand_new_key(ctx):
    # The live-demo setting: a key created moments ago is flagged for both controls.
    ctx.client("iam").create_user(UserName="fresh")
    key_id = ctx.client("iam").create_access_key(UserName="fresh")["AccessKey"]["AccessKeyId"]
    demo = dataclasses.replace(ctx, thresholds=Thresholds(key_unused_days=0, key_max_age_days=0))

    [f] = check(demo)

    assert f.evidence["access_key_id"] == key_id
    assert f.cis_controls == ["1.12", "1.14"]
