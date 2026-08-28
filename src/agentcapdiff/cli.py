from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .diffing import compare_snapshots, write_snapshot
from .discovery import DiscoveryLimitError
from .formats import json_report, markdown_diff_report, sarif_report, text_report
from .outputio import OutputWriteError, atomic_write_text
from .scanner import scan


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentcapdiff",
        description="Audit and diff AI-agent capabilities.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan tool definitions and evaluate policy.")
    scan_p.add_argument("path", nargs="?", default=".")
    scan_p.add_argument("--policy", default="agentcapdiff.yaml")
    scan_p.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan_p.add_argument("--output")
    scan_p.add_argument("--fail-on", choices=["never", "medium", "high"], default="medium")

    snap_p = sub.add_parser(
        "snapshot",
        help="Write a capability snapshot for later diffing.",
    )
    snap_p.add_argument("path", nargs="?", default=".")
    snap_p.add_argument("--policy", default="agentcapdiff.yaml")
    snap_p.add_argument("--output", required=True)

    diff_p = sub.add_parser("diff", help="Compare two capability snapshots.")
    diff_p.add_argument("base")
    diff_p.add_argument("head")
    diff_p.add_argument("--format", choices=["json", "markdown"], default="json")
    diff_p.add_argument("--output")
    return parser


def _should_fail(severity: str, threshold: str) -> bool:
    if threshold == "never":
        return False
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    minimum = {"medium": 2, "high": 3}[threshold]
    return order.get(severity, 0) >= minimum


def _report_output_error(exc: OutputWriteError) -> None:
    print(f"agentcapdiff: unsafe or invalid output path: {exc}", file=sys.stderr)


def _write_or_print(report: str, output: str | None) -> bool:
    if output:
        suffix = "\n" if not report.endswith("\n") else ""
        try:
            atomic_write_text(Path(output), report + suffix)
        except OutputWriteError as exc:
            _report_output_error(exc)
            return False
    else:
        print(report)
    return True


def _scan_or_report_error(path: Path, policy: Path | None):
    try:
        return scan(path, policy)
    except (DiscoveryLimitError, FileNotFoundError, ValueError) as exc:
        print(f"agentcapdiff: unsafe or invalid scan input/policy: {exc}", file=sys.stderr)
        return None


def _diff_or_report_error(base: Path, head: Path):
    try:
        return compare_snapshots(base, head)
    except (FileNotFoundError, ValueError) as exc:
        print(f"agentcapdiff: unsafe or invalid snapshot input: {exc}", file=sys.stderr)
        return None


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "scan":
        policy = Path(args.policy) if args.policy else None
        if policy and not policy.exists():
            policy = None
        result = _scan_or_report_error(Path(args.path), policy)
        if result is None:
            return 3
        report = {
            "text": text_report,
            "json": json_report,
            "sarif": sarif_report,
        }[args.format](result)
        if not _write_or_print(report, args.output):
            return 3
        return 2 if _should_fail(result.max_severity, args.fail_on) else 0

    if args.command == "snapshot":
        policy = Path(args.policy) if args.policy else None
        if policy and not policy.exists():
            policy = None
        result = _scan_or_report_error(Path(args.path), policy)
        if result is None:
            return 3
        try:
            write_snapshot(result, Path(args.output))
        except OutputWriteError as exc:
            _report_output_error(exc)
            return 3
        return 0

    if args.command == "diff":
        diff = _diff_or_report_error(Path(args.base), Path(args.head))
        if diff is None:
            return 3
        if args.format == "markdown":
            report = markdown_diff_report(diff)
        else:
            report = json.dumps(diff, indent=2)
        if not _write_or_print(report, args.output):
            return 3
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
