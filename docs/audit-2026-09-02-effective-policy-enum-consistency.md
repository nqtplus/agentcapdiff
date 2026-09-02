# Audit #30 — Effective policy enum consistency

Date: 2026-09-02

## Scope

Review the `ScanResult.seal(policy)` boundary for policy objects supplied directly by library callers rather than loaded from YAML.

## Finding

Audits #27 and #29 made file-loaded policy values strict, but `_validate_effective_policy()` only enforced the `max_risk_score` domain. A caller could still construct a Python `Policy` object with invalid `unknown_scope` or malformed trust-boundary annotations, then provide a matching policy record to a manually assembled `ScanResult`.

For example, an invalid in-process policy could carry a list for `unknown_scope` or `TrustBoundary.trust`. These values could survive `policy_to_record()` and be sealed even though the trusted snapshot reader would reject the resulting policy metadata. Other malformed trust-boundary shapes could fail later with incidental serializer errors rather than a controlled consistency exception.

This creates a producer/consumer inconsistency between the library seal boundary and the hardened snapshot artifact boundary.

## Remediation

Extend `_validate_effective_policy()` before policy serialization/evaluation to require:

- `max_risk_score` remains a non-boolean integer from 0 through 100;
- `unknown_scope` is one of `deny`, `review`, or `ignore` and is a string;
- `trust_boundaries` is a mapping with string keys;
- each trust-boundary value is a `TrustBoundary`;
- each boundary label is a non-empty string;
- each trust level is one of `trusted`, `untrusted`, or `unknown` and is a string;
- each trust-boundary note is a string.

Invalid direct-library policy objects now fail with `ScanResultConsistencyError` before `policy_to_record()` or `evaluate_policy()` can produce inconsistent output.

## Compatibility

Valid file-loaded policies are unchanged. Valid direct-library `Policy(...)` objects preserve their existing behavior and still seal normally. No capability inference, risk scoring, policy precedence, snapshot/JSON/SARIF structure, CLI syntax, package version, target-code execution, or endpoint behavior changes.

## Residuals

This audit focuses on effective-policy enum/trust annotation consistency. Other deliberately malformed in-process dataclass fields remain subject to their own public type contracts and may warrant separate review only if they can cross a sealed output boundary without being detected.
