"""boto3 session handling and the per-scan ScanContext."""

from __future__ import annotations

import csv
import io
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import boto3

# Values the credential report uses instead of a timestamp.
_REPORT_NO_VALUE = {"N/A", "no_information", "not_supported", ""}


@dataclass(frozen=True)
class Thresholds:
    """Tunable limits. Defaults follow CIS v3.0.0; the live demo lowers them."""

    key_unused_days: int = 45  # CIS 1.12
    key_max_age_days: int = 90  # CIS 1.14


def create_session(profile: str | None = None, region: str | None = None) -> boto3.Session:
    return boto3.Session(profile_name=profile, region_name=region)


@dataclass
class ScanContext:
    """Everything a check needs. Build one per scan run."""

    session: boto3.Session
    regions: list[str]
    thresholds: Thresholds = field(default_factory=Thresholds)
    # Reference time for age calculations; tests pin it for deterministic results.
    now: datetime = field(default_factory=lambda: datetime.now(UTC))
    report_poll_interval: float = 2.0  # seconds between generate_credential_report polls
    report_timeout: float = 60.0
    _credential_report: list[dict[str, str]] | None = field(default=None, init=False, repr=False)

    def client(self, service: str, region: str | None = None) -> Any:
        return self.session.client(service, region_name=region or self.regions[0])

    def credential_report(self) -> list[dict[str, str]]:
        """Return the IAM credential report as one dict per row (CSV header → value).

        Generated and fetched once per ScanContext, then cached. Values are raw strings;
        use `parse_report_timestamp` for date columns.
        """
        if self._credential_report is None:
            self._credential_report = self._fetch_credential_report()
        return self._credential_report

    def _fetch_credential_report(self) -> list[dict[str, str]]:
        iam = self.client("iam")
        deadline = time.monotonic() + self.report_timeout
        while iam.generate_credential_report()["State"] != "COMPLETE":
            if time.monotonic() > deadline:
                raise TimeoutError("IAM credential report was not ready in time")
            time.sleep(self.report_poll_interval)
        content = iam.get_credential_report()["Content"]
        return list(csv.DictReader(io.StringIO(content.decode("utf-8"))))


def parse_report_timestamp(value: str) -> datetime | None:
    """Parse a credential report date column; None for N/A, no_information, etc."""
    if value in _REPORT_NO_VALUE:
        return None
    return datetime.fromisoformat(value)
