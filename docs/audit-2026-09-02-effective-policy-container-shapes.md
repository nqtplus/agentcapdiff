# Audit #33 — Effective policy container shapes

Date: 2026-09-02

## Scope

Review the `ScanResult.seal(policy)` producer boundary for directly constructed Python `Policy` objects whose runtime container shapes do not match the file-loaded policy model.

## Finding

The YAML loader normalizes policy collections before evaluation, but a library caller can construct `Policy(...)` directly with runtime values that satisfy neither the dataclass annotation nor the loader contract.

The most important case is a string supplied where a collection is expected. Python treats strings as iterables, so a value such as `Policy(deny="shell.execute")` can be serialized/evaluated as individual characters instead of the intended capability selector. Similar ambiguity exists for `require_review`, `allow_by_tool` values, scope-constraint containers, suppression containers, and `sources`.

This is fail-open or incidental-failure behavior at the sealed-result producer boundary rather than a controlled consistency rejection.

## Remediation

`_validate_effective_policy()` now validates container shape before `policy_to_record()` and policy-result sealing:

- `deny` and `require_review` must be string collections;
- `allow_by_tool` must be a mapping with non-empty string keys and string-collection values;
- `scope_constraints` must be a mapping to `ScopeConstraint` values with valid scope kinds and string collections;
- `suppressions` must be a list/tuple of `Suppression` values;
- `sources` must be a list/tuple of strings;
- existing threshold, unknown-scope, and trust-boundary validation remains unchanged.

For direct-library compatibility, reasonable collection variants (`set`, `frozenset`, `list`, `tuple`) remain accepted where their semantics are unambiguous. The hardening rejects strings and mapping-shaped impostors instead of relying on Python iterable behavior.

## Regression coverage

Regression tests verify that:

- `deny="shell.execute"` fails with `ScanResultConsistencyError` before sealing;
- malformed review, allowlist, scope, suppression, and source containers fail closed;
- malformed scope-kind containers fail closed;
- valid list/tuple/set variants still seal and remain internally consistent.

## Non-goals

This audit does not change capability inference, risk scoring, policy precedence, YAML syntax, public snapshot/JSON/SARIF structure, CLI syntax, package version, or historical snapshot behavior.
