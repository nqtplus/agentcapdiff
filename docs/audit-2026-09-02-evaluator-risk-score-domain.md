# Audit #35 — Evaluator risk-score domain binding

## Scope

Bind the direct-library `evaluate_policy()` risk-score input to the same integer `0..100` domain used by `ScanResult.risk_score` and snapshot validation.

## Finding

`ScanResult.risk_score` always produces an integer capped at 100, and untrusted snapshots reject risk scores that are booleans, non-integers, negative, or above 100. Direct callers of `evaluate_policy()` could still pass values outside that domain.

Python treats `bool` as an `int`, and floats or out-of-range integers are orderable against the configured threshold. A malformed direct call could therefore bypass or distort the stable `risk.threshold` decision instead of failing closed. Strings and unrelated objects could also fail through incidental comparison exceptions.

## Remediation

- validate `risk_score` before any policy finding generation;
- require an actual integer, rejecting booleans;
- require `0 <= risk_score <= 100`;
- raise a controlled `ValueError` for malformed direct-library values;
- preserve the existing threshold rule: a finding is emitted only when `risk_score > max_risk_score`.

## Regression coverage

Permanent tests cover:

- bool, negative, above-100, float, string, and `None` rejection;
- valid `0`, `60`, and `100` values;
- unchanged threshold behavior at `60` and `61` for a threshold of 60.

## Security effect

The evaluator can no longer make a security decision using a risk score that cannot be represented by a normal scanner result or accepted snapshot. Direct-library evaluation now shares the same risk-score numeric domain as the rest of the stable 1.x pipeline.

## Non-goals

This audit does not change capability risk weights, risk aggregation, policy precedence, threshold semantics, snapshot schemas, CLI syntax, package version, target-code execution, endpoint probing, credentials, or historical snapshot behavior.
