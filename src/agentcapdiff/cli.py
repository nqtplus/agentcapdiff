from __future__ import annotations

import argparse
import json
from pathlib import Path

from .diffing import compare_snapshots, write_snapshot
from .formats import json_report, sarif_report, text_report
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
    scan_p.add_argument("--fail-on", choices=["never", "medium", "high"], default="high")

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
    return parser


def _should_fail(severity: str, threshold: str) -> bool:
    if threshold == "never":
        return False
    order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    minimum = {"medium": 2, "high": 3}[threshold]
    return order.get(severity, 0) >= minimum


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "scan":
        policy = Path(args.policy) if args.policy else None
        if policy and not policy.exists():
            policy = None
        result = scan(Path(args.path), policy)
        report = {
            "text": text_report,
            "json": json_report,
            "sarif": sarif_report,
        }[args.format](result)
        if args.output:
            suffix = "\n" if not report.endswith("\n") else ""
            Path(args.output).write_text(report + suffix, encoding="utf-8")
        else:
            print(report)
        return 2 if _should_fail(result.max_severity, args.fail_on) else 0

    if args.command == "snapshot":
        policy = Path(args.policy) if args.policy else None
        if policy and not policy.exists():
            policy = None
        write_snapshot(scan(Path(args.path), policy), Path(args.output))
        return 0

    if args.command == "diff":
        print(json.dumps(compare_snapshots(Path(args.base), Path(args.head)), indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
