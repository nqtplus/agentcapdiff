# Audit #24 — Effective policy threshold consistency

## Scope

This audit checks whether the effective `max_risk_score` used by scanner-sealed results stays inside the same 0–100 semantic domain as `ScanResult.risk_score` and snapshot policy validation.

## Finding

`Policy.max_risk_score` is intended to bound a risk score that is itself capped at 100. Snapshot ingestion already requires `policy.max_risk_score` to be an integer from 0 through 100.

The effective-policy path used by scanning did not enforce that same invariant before evaluation/sealing. A repository policy containing `max_risk_score: 999` could therefore be accepted, making the global risk threshold unreachable for any scanner result. The scanner could then serialize a policy value that the snapshot reader rejects as invalid, creating a producer/consumer inconsistency where AgentCapDiff could produce an artifact that its own diff path would refuse to load.

Manual library construction could also supply booleans, negative values, values above 100, floats, or strings to `Policy.max_risk_score` and attempt to seal a result without a dedicated effective-policy validation boundary.

## Remediation

`seal_scan_result()` now validates the effective runtime policy before converting it to the sealed policy record or re-evaluating findings.

The effective `max_risk_score` must be:

- an integer;
- not a boolean;
- greater than or equal to 0;
- less than or equal to 100.

Invalid effective policies fail closed with `ScanResultConsistencyError`, which is a `ValueError` and therefore follows the CLI's existing controlled invalid-input path.

This validation is deliberately placed at the scanner seal boundary. It protects every scanner-produced output and manually sealed `ScanResult` without changing the historical behavior of an unsealed standalone `Policy` object.

## Permanent regressions

Tests cover:

- boolean, negative, above-100, floating-point, and string thresholds being rejected when a result is sealed;
- boundary values 0 and 100 remaining valid;
- CLI `snapshot` with `max_risk_score: 999` returning exit code 3 before any snapshot file is written.

## Security effect

A policy threshold can no longer be moved outside the reachable scanner risk domain to silently disable the aggregate risk gate, and scanner-produced snapshots cannot contain an out-of-range threshold that the trusted snapshot reader would reject later.

## Compatibility

Valid integer thresholds from 0 through 100 are unchanged. Capability rules, risk weights, scope semantics, policy precedence, public JSON/SARIF/snapshot structure, and package version remain unchanged at `1.0.0`.

Unsealed standalone `Policy` instances remain ordinary library objects; the strict guarantee applies when a policy becomes effective security evidence for a sealed scan result.

## Follow-up boundary

Raw YAML duplicate-key ambiguity is a separate parser-layer concern and is intentionally deferred to the next audit rather than mixed into this semantic invariant change.
