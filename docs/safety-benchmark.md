# Safety benchmark

AgentCapDiff v0.9 adds a reproducible static benchmark intended to measure dangerous misses without turning a clean result into a safety guarantee.

## What is measured

The committed corpus contains positive, negative, and ambiguous fixtures. Each case declares expected capabilities and, separately, the high-risk capabilities whose absence is treated as a dangerous false negative.

The benchmark emits a machine-readable JSON summary with separate counters for:

- high-risk false negatives;
- nuisance false positives;
- capabilities whose effective scope remains unknown;
- parser failures.

`benchmarks/baseline.json` is the release baseline. CI fails if high-risk false negatives or parser failures exceed that baseline. False positives and unknown scope are reported explicitly rather than folded into a single score.

Run locally:

```bash
python -m agentcapdiff.benchmark --output benchmark-summary.json
```

## Regression-fixture rule

Every fix for a classification bug, parser/security bug, or previously missed dangerous capability must add or update a permanent sanitized fixture and its expected outcome. Baseline changes require review and must never hide a newly introduced dangerous miss.

## Limitations

This benchmark exercises static serialized inputs only. It does not execute or import target repository code, probe endpoints, use credentials, or establish runtime reachability. The corpus is deliberately finite and cannot prove an agent is safe. Unsupported or dynamic behavior can remain unknown, and **unknown is not safe**.
