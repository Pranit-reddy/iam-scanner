"""Render a ScanResult as a Markdown report."""

from __future__ import annotations

import json
from collections import Counter
from datetime import UTC, datetime

from iam_scanner.controls import BENCHMARK, get_control
from iam_scanner.models import Finding, ScanResult, Severity

_SEVERITIES_DESC = sorted(Severity, reverse=True)


def render_markdown(
    result: ScanResult,
    account_id: str,
    regions: list[str],
    generated_at: datetime,
) -> str:
    """Build the full report. `generated_at` is passed in so output is reproducible."""
    findings = result.sorted_findings()
    sections = [
        _header(account_id, regions, generated_at),
        _summary(result, findings),
        _findings_table(findings),
        _details(findings),
        _check_status(result),
    ]
    return "\n\n".join(s for s in sections if s) + "\n"


def _header(account_id: str, regions: list[str], generated_at: datetime) -> str:
    timestamp = generated_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    return "\n".join(
        [
            "# IAM Misconfiguration Scan Report",
            "",
            "| | |",
            "|---|---|",
            f"| **Account** | `{account_id}` |",
            f"| **Region(s)** | {', '.join(regions)} |",
            f"| **Generated** | {timestamp} |",
            f"| **Benchmark** | {BENCHMARK} |",
        ]
    )


def _summary(result: ScanResult, findings: list[Finding]) -> str:
    counts = Counter(f.severity for f in findings)
    total_checks = len({f.check_id for f in findings}) + len(result.passed) + len(result.errors)
    return "\n".join(
        [
            "## Summary",
            "",
            "| " + " | ".join(s.label for s in _SEVERITIES_DESC) + " |",
            "|" + "---|" * len(_SEVERITIES_DESC),
            "| " + " | ".join(str(counts[s]) for s in _SEVERITIES_DESC) + " |",
            "",
            f"**{_plural(len(findings), 'finding')}** from {_plural(total_checks, 'check')}: "
            f"{len(result.passed)} passed, {len(result.errors)} errored.",
        ]
    )


def _findings_table(findings: list[Finding]) -> str:
    lines = ["## Findings", ""]
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)
    lines += [
        "| # | Severity | Finding | Resource | CIS control(s) |",
        "|---|---|---|---|---|",
    ]
    for i, f in enumerate(findings, 1):
        lines.append(
            f"| {i} | {f.severity.label} | [{_cell(_escape(f.title))}](#{i}-{_anchor(f.title)}) "
            f"| `{_cell(f.resource_id)}` | {', '.join(f.cis_controls)} |"
        )
    return "\n".join(lines)


def _details(findings: list[Finding]) -> str:
    if not findings:
        return ""
    return "## Details\n\n" + "\n\n---\n\n".join(
        _finding_section(i, f) for i, f in enumerate(findings, 1)
    )


def _finding_section(index: int, f: Finding) -> str:
    controls = [get_control(cid) for cid in f.cis_controls]
    lines = [
        f"### {index}. {_escape(f.title)}",
        "",
        f"- **Severity:** {f.severity.label}",
        f"- **Resource:** `{f.resource_id}` ({f.resource_type}, {f.region})",
        f"- **Check:** `{f.check_id}`",
        "",
        _escape(f.description),
        "",
        "**CIS controls**",
        "",
        *(f"- **{c.id}**: {_escape(c.title)}" for c in controls),
        "",
        "**Evidence**",
        "",
    ]
    if f.evidence:
        lines += ["```json", json.dumps(f.evidence, indent=2, sort_keys=True, default=str), "```"]
    else:
        lines.append("_None recorded._")
    lines += ["", "**Remediation**"]
    for c in controls:
        lines += ["", f"_{c.id}: {_escape(c.title)}_", "", *_paragraphs(c.remediation)]
    return "\n".join(lines)


def _check_status(result: ScanResult) -> str:
    lines = ["## Check status", "", "### Passed", ""]
    lines += [f"- `{cid}`" for cid in sorted(result.passed)] or ["_None._"]
    lines += ["", "### Errored", ""]
    lines += [
        f"- `{e.check_id}`: {e.message}" for e in sorted(result.errors, key=lambda e: e.check_id)
    ] or ["_None._"]
    return "\n".join(lines)


def _paragraphs(text: str) -> list[str]:
    """Each line of stored remediation text becomes its own Markdown paragraph."""
    out: list[str] = []
    for line in text.splitlines():
        out += [line, ""]
    return out[:-1]


def _escape(text: str) -> str:
    """Escape Markdown syntax in free text, e.g. so '*:*' isn't rendered as italics."""
    for ch in "\\`*_[]":
        text = text.replace(ch, "\\" + ch)
    return text


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def _anchor(title: str) -> str:
    """Approximate GitHub's heading-anchor slug."""
    slug = "".join(ch for ch in title.lower() if ch.isalnum() or ch in " -")
    return slug.replace(" ", "-")


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"
