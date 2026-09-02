# Audit #31 — Effective suppression expiry enforcement

Date: 2026-09-02

## Scope

Review direct-library `Policy(suppressions=...)` evaluation for parity with YAML-loaded suppression safety requirements.

## Finding

The YAML policy loader requires every suppression to have a non-empty reason and a valid, unexpired date. Directly constructed `Policy` objects did not receive the same validation inside `evaluate_policy()`.

As a result, a caller could construct an expired `Suppression` targeting a HIGH finding such as `capability.denied`. `_canonical_suppressions()` canonicalized the selector but did not check expiry, so `_apply_suppressions()` could still convert the HIGH finding to INFO after the exception had expired.

This is a real policy bypass in the direct-library path, not only a producer/consumer formatting inconsistency.

## Remediation

`_canonical_suppressions()` now enforces the same effective invariants before any suppression can match a finding:

- each entry must be a `Suppression`;
- `rule_id` is required;
- `reason` must be a non-empty string;
- `expires` must be a date, not a datetime or other type;
- suppressions with an expiry before the current UTC date are rejected;
- capability/tool selectors, when present, must be non-empty strings;
- duplicate canonical selectors remain rejected;
- direct suppression reasons are trimmed to match file-loader normalization.

A suppression remains valid through its expiry date, matching the documented 1.x policy contract.

## Security result

An expired direct-library suppression can no longer downgrade an active HIGH/MEDIUM policy finding. Invalid suppression policy fails closed with `ValueError` before `_apply_suppressions()` runs.

## Compatibility

Valid active suppressions are unchanged. File-loaded policies already met these invariants, so normal scanner behavior and policy precedence are preserved. No capability inference, risk scoring, snapshot/JSON/SARIF structure, CLI syntax, package version, target-code execution, endpoint probing, or credential behavior changes.
