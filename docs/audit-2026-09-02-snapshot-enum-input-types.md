# Audit #28 — Snapshot enum input type safety

Date: 2026-09-02

## Scope

Review externally supplied snapshot enum fields for hostile non-string JSON values that could reach set-membership checks before type validation.

## Finding

Two snapshot fields reached membership checks without a prior string-type guard:

- top-level `max_severity`;
- `policy.unknown_scope`.

Python set/frozenset membership hashes the candidate. A JSON array or object is represented as a Python `list` or `dict`, which is unhashable. Therefore hostile snapshots such as:

```json
{"max_severity": []}
```

or:

```json
{"policy": {"unknown_scope": {"value": "review"}}}
```

could raise an uncaught `TypeError` instead of the documented `SnapshotArtifactError` fail-closed path. The trusted PR capability-diff workflow treats snapshot files as untrusted static data, so this is a trust-boundary robustness defect.

Nested enum fields for findings, scopes, graph paths, and trust-boundary annotations already pass through `_optional_string()` before their membership checks and were not affected.

## Remediation

- require top-level `max_severity` to be a string before checking `_SEVERITIES`;
- require `policy.unknown_scope` to be a string before checking `_UNKNOWN_SCOPE`;
- preserve existing accepted enum values and all public snapshot structure/fingerprint behavior;
- add regressions for list and mapping inputs, CLI exit-code-3 normalization, and valid enum compatibility.

## Security properties

After this change, malformed enum values at these two snapshot boundaries fail with `SnapshotArtifactError` rather than escaping as `TypeError`. No target repository code is executed, imported, probed, or trusted.

## Non-goals / residuals

This audit does not change raw YAML policy enum parsing. Raw policy `unknown_scope` and `trust_boundaries.*.trust` are a separate parser boundary and should be reviewed independently rather than coupled to snapshot hardening.

It also does not claim arbitrary in-process Python object safety; the guarantee concerns externally supplied snapshot artifacts processed by `load_snapshot()` and CLI `diff`.
