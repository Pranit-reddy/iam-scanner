"""Core data types shared by checks and the report."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Finding severity. Higher value = more severe, so `max()` and sorting work directly."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.capitalize()


@dataclass(frozen=True)
class Finding:
    """One misconfigured resource, as reported by a single check."""

    check_id: str
    resource_type: str  # CloudFormation-style, e.g. "AWS::IAM::User"
    resource_id: str  # ARN, or name/ID when the resource has no ARN
    region: str  # "global" for IAM
    severity: Severity
    title: str
    description: str
    cis_controls: list[str]
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CheckError:
    """A check that could not complete, e.g. because of AccessDenied."""

    check_id: str
    message: str


@dataclass
class ScanResult:
    """Everything a scan run produced, ready for the report renderer."""

    findings: list[Finding] = field(default_factory=list)
    passed: list[str] = field(default_factory=list)  # check_ids with no findings
    errors: list[CheckError] = field(default_factory=list)

    def sorted_findings(self) -> list[Finding]:
        """Findings ordered Critical → Low, then by check and resource for stable output."""
        return sorted(self.findings, key=lambda f: (-f.severity, f.check_id, f.resource_id))
