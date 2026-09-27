"""Command-line interface: build a ScanContext, run checks, write the Markdown report."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError

from iam_scanner import CIS_BENCHMARK_VERSION, __version__
from iam_scanner.aws import ScanContext, Thresholds, create_session
from iam_scanner.checks import CHECKS, check_id, run_all
from iam_scanner.models import ScanResult, Severity
from iam_scanner.report.markdown import render_markdown

EXIT_OK = 0
EXIT_FINDINGS = 1  # Critical or High findings exist
EXIT_ERROR = 2  # bad arguments, or AWS couldn't be reached at all

DEFAULT_REGION = "us-east-1"
FAILING_SEVERITIES = {Severity.CRITICAL, Severity.HIGH}


def build_parser() -> argparse.ArgumentParser:
    available = [check_id(c) for c in CHECKS]
    parser = argparse.ArgumentParser(
        prog="iam-scanner",
        description=(
            f"Scan an AWS account for IAM misconfigurations mapped to CIS AWS Foundations "
            f"Benchmark v{CIS_BENCHMARK_VERSION}, and write a Markdown report."
        ),
        epilog=(
            f"Available checks: {', '.join(available)}. Exit codes: 0 = no Critical/High "
            f"findings, 1 = Critical/High findings, 2 = error."
        ),
    )
    parser.add_argument("--profile", help="AWS profile name (default: standard credential chain)")
    parser.add_argument(
        "--region",
        help=f"region for regional checks (default: the profile's region, else {DEFAULT_REGION})",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("reports/scan.md"),
        help="where to write the Markdown report (default: reports/scan.md)",
    )
    parser.add_argument(
        "--key-max-age-days",
        type=_non_negative_int,
        default=Thresholds.key_max_age_days,
        help="flag access keys older than this (CIS 1.14; default: %(default)s)",
    )
    parser.add_argument(
        "--key-unused-days",
        type=_non_negative_int,
        default=Thresholds.key_unused_days,
        help="flag access keys unused for this many days or more (CIS 1.12; default: %(default)s)",
    )
    parser.add_argument(
        "--checks",
        help="comma-separated check IDs to run (default: all)",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    only = _parse_checks(parser, args.checks)

    try:
        session = create_session(profile=args.profile, region=args.region)
        region = args.region or session.region_name or DEFAULT_REGION
        ctx = ScanContext(
            session=session,
            regions=[region],
            thresholds=Thresholds(
                key_unused_days=args.key_unused_days,
                key_max_age_days=args.key_max_age_days,
            ),
        )
        account_id = ctx.client("sts").get_caller_identity()["Account"]
        result = run_all(ctx, only=only)
    except (BotoCoreError, ClientError) as exc:
        print(f"iam-scanner: cannot scan: {exc}", file=sys.stderr)
        return EXIT_ERROR

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        render_markdown(result, account_id=account_id, regions=ctx.regions, generated_at=ctx.now)
    )
    print(_summary_line(result, args.output))
    failing = any(f.severity in FAILING_SEVERITIES for f in result.findings)
    return EXIT_FINDINGS if failing else EXIT_OK


def _parse_checks(parser: argparse.ArgumentParser, value: str | None) -> set[str] | None:
    if value is None:
        return None
    requested = {name.strip() for name in value.split(",") if name.strip()}
    unknown = requested - {check_id(c) for c in CHECKS}
    if unknown or not requested:
        parser.error(f"unknown check(s): {', '.join(sorted(unknown)) or '(none given)'}")
    return requested


def _non_negative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be 0 or greater")
    return number


def _summary_line(result: ScanResult, output: Path) -> str:
    counts = Counter(f.severity for f in result.findings)
    by_severity = ", ".join(
        f"{counts[s]} {s.label.lower()}" for s in sorted(Severity, reverse=True)
    )
    ran = len({f.check_id for f in result.findings}) + len(result.passed) + len(result.errors)
    return (
        f"{len(result.findings)} findings ({by_severity}) from {ran} checks: "
        f"{len(result.passed)} passed, {len(result.errors)} errored. Report: {output}"
    )
