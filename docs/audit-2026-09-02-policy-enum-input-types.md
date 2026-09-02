# Audit #29 — Raw policy enum input type safety

Date: 2026-09-02

## Scope

Review raw YAML policy enum fields for hostile non-string values that could reach set-membership checks before type validation.

## Finding

Two raw policy paths were vulnerable to uncaught `TypeError` on YAML sequences or mappings:

- top-level `unknown_scope`;
- `trust_boundaries.<tool>.trust` in mapping-form trust annotations.

Both values were checked with Python set/frozenset membership before requiring a string. YAML sequences and mappings become Python `list` and `dict` values, which are unhashable. As a result, malformed or hostile policy input could escape the documented invalid-policy path instead of failing with controlled `ValueError` and CLI exit code 3.

This is separate from Audit #28, which hardened the corresponding externally supplied snapshot boundary.

## Remediation

- add `_UNKNOWN_SCOPE` as the canonical allowed-value set;
- add strict `_load_unknown_scope()` validation that requires a string before membership;
- add strict `_load_trust_level()` validation that requires a string before membership;
- preserve existing error text for invalid values;
- preserve all valid enum strings and the short-form trust-boundary default of `trust: unknown`;
- add loader and CLI regressions for list, mapping, boolean, number, and null inputs.

## Security properties

Malformed enum values now fail through controlled `ValueError` paths rather than uncaught `TypeError`. The scanner continues to treat policy files as static data and does not execute or import target repository code.

## Compatibility

Accepted values remain unchanged:

- `unknown_scope`: `deny`, `review`, `ignore`;
- trust level: `trusted`, `untrusted`, `unknown`.

No capability inference, risk scoring, scope semantics, policy precedence, snapshot/JSON/SARIF structure, package version, or target-code execution behavior changes.

## Residuals

This audit covers raw policy enum type safety only. It does not claim arbitrary manually constructed in-process `Policy` object type safety beyond existing seal/evaluation invariants, and it does not broaden policy syntax.
