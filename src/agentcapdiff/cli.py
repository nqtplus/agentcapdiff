from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .diffing import compare_snapshots, write_snapshot
from .discovery import DiscoveryLimitError
from .formats import json_report, markdown_diff_report, sarif_report, text_report
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


def _write_or_print(report: str, output: str | None) -> None:
    if output:
        suffix = "\n" if not report.endswith("\n") else ""
        Path(output).write_text(report + suffix, encoding="utf-8")
    else:
        print(report)


def _scan_or_report_error(path: Path, policy: Path | None):
    try:
        return scan(path, policy)
    except (DiscoveryLimitError, FileNotFoundError) as exc:
        print(f"agentcapdiff: unsafe or invalid scan input: {exc}", file=sys.stderr)
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
        _write_or_print(report, args.output)
        return 2 if _should_fail(result.max_severity, args.fail_on) else 0

    if args.command == "snapshot":
        policy = Path(args.policy) if args.policy else None
        if policy and not policy.exists():
            policy = None
        result = _scan_or_report_error(Path(args.path), policy)
        if result is None:
            return 3
        write_snapshot(result, Path(args.output))
        return 0

    if args.command == "diff":
        diff = compare_snapshots(Path(args.base), Path(args.head))
        if args.format == "markdown":
            report = markdown_diff_report(diff)
        else:
            report = json.dumps(diff, indent=2)
        _write_or_print(report, args.output)
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
