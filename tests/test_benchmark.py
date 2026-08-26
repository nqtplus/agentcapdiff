from pathlib import Path

from agentcapdiff.benchmark import compare_baseline, run_benchmark

ROOT = Path(__file__).resolve().parents[1]


def test_safety_benchmark_has_no_dangerous_misses_or_parser_failures() -> None:
    summary = run_benchmark(ROOT / "benchmarks" / "manifest.json")
    metrics = summary["metrics"]
    assert metrics["high_risk_false_negatives"] == 0
    assert metrics["nuisance_false_positives"] == 0
    assert metrics["parser_failures"] == 0
    assert metrics["unknown_scope_count"] >= 1


def test_baseline_gate_rejects_worse_high_risk_false_negatives() -> None:
    summary = {
        "metrics": {
            "high_risk_false_negatives": 1,
            "parser_failures": 0,
        }
    }
    failures = compare_baseline(
        summary,
        {"max_high_risk_false_negatives": 0, "max_parser_failures": 0},
    )
    assert failures
    assert "false negatives worsened" in failures[0]
