from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .discovery import DiscoveryLimitError
from .outputio import OutputWriteError, atomic_write_text
from .scanner import scan

HIGH_RISK_CAPABILITIES = {
    "filesystem.write",
    "github.write",
    "secrets.access",
    "shell.execute",
}


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    path: Path
    expected: frozenset[str]
    expected_high_risk: frozenset[str]


def _load_manifest(path: Path) -> list[BenchmarkCase]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = []
    for raw in payload.get("cases", []):
        expected = frozenset(str(item) for item in raw.get("expected_capabilities", []))
        declared_high = frozenset(str(item) for item in raw.get("expected_high_risk", []))
        if not declared_high.issubset(expected):
            raise ValueError(f"{raw.get('name', '<unnamed>')}: expected_high_risk must be expected")
        cases.append(
            BenchmarkCase(
                name=str(raw["name"]),
                path=(path.parent / str(raw["path"])).resolve(),
                expected=expected,
                expected_high_risk=declared_high,
            )
        )
    if not cases:
        raise ValueError("benchmark manifest must contain at least one case")
    return cases


def run_benchmark(manifest: Path) -> dict[str, Any]:
    case_results: list[dict[str, Any]] = []
    high_risk_false_negatives = 0
    nuisance_false_positives = 0
    unknown_scope_count = 0
    parser_failures = 0

    for case in _load_manifest(manifest):
        try:
            result = scan(case.path)
        except (DiscoveryLimitError, FileNotFoundError, ValueError) as exc:
            parser_failures += 1
            case_results.append(
                {
                    "name": case.name,
                    "status": "parser_failure",
                    "error_type": type(exc).__name__,
                }
            )
            continue

        observed = {cap.id for cap in result.capabilities}
        missing_high = sorted(case.expected_high_risk - observed)
        unexpected = sorted(observed - case.expected)
        unknown = sum(1 for cap in result.capabilities if cap.scope.kind == "unknown")
        high_risk_false_negatives += len(missing_high)
        nuisance_false_positives += len(unexpected)
        unknown_scope_count += unknown
        case_results.append(
            {
                "name": case.name,
                "status": "ok",
                "expected_capabilities": sorted(case.expected),
                "observed_capabilities": sorted(observed),
                "missing_high_risk": missing_high,
                "unexpected_capabilities": unexpected,
                "unknown_scope_count": unknown,
            }
        )

    return {
        "schema_version": 1,
        "cases": len(case_results),
        "metrics": {
            "high_risk_false_negatives": high_risk_false_negatives,
            "nuisance_false_positives": nuisance_false_positives,
            "unknown_scope_count": unknown_scope_count,
            "parser_failures": parser_failures,
        },
        "case_results": case_results,
        "limitations": [
            "Static fixtures do not prove runtime safety or reachability.",
            "Unknown scope is reported explicitly and is not treated as safe.",
            "The corpus measures covered patterns only; it is not exhaustive.",
        ],
    }


def compare_baseline(summary: dict[str, Any], baseline: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    actual = summary["metrics"]
    allowed_fn = int(baseline.get("max_high_risk_false_negatives", 0))
    if int(actual["high_risk_false_negatives"]) > allowed_fn:
        failures.append(
            "high-risk false negatives worsened: "
            f"{actual['high_risk_false_negatives']} > baseline {allowed_fn}"
        )
    allowed_parser = int(baseline.get("max_parser_failures", 0))
    if int(actual["parser_failures"]) > allowed_parser:
        failures.append(
            f"parser failures worsened: {actual['parser_failures']} > baseline {allowed_parser}"
        )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run AgentCapDiff's static safety benchmark.")
    parser.add_argument("--manifest", default="benchmarks/manifest.json")
    parser.add_argument("--baseline", default="benchmarks/baseline.json")
    parser.add_argument("--output", default="benchmark-summary.json")
    args = parser.parse_args(argv)

    summary = run_benchmark(Path(args.manifest))
    try:
        atomic_write_text(Path(args.output), json.dumps(summary, indent=2) + "\n")
    except OutputWriteError as exc:
        print(f"benchmark gate: unsafe or invalid output path: {exc}", file=sys.stderr)
        return 1
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    failures = compare_baseline(summary, baseline)
    print(json.dumps(summary["metrics"], sort_keys=True))
    for failure in failures:
        print(f"benchmark gate: {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
