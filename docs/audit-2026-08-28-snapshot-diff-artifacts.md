# Audit 2026-08-28 — snapshot/diff artifact safety

Scope: one post-v1.0 audit pass covering hostile capability-snapshot artifacts, diff resource bounds, and fail-closed compatibility. This pass does not change capability/policy semantics, output schemas, or package version.

## Findings

1. `compare_snapshots()` read both JSON artifacts with unbounded `Path.read_text()` + `json.loads()`. Large or deeply nested artifacts could therefore consume unbounded parser/traversal work relative to the rest of the scanner's bounded-input model.
2. Snapshot paths did not reject symlink artifacts, so an untrusted artifact path could redirect the diff reader to another local file selected through filesystem metadata.
3. Stable fields such as `capabilities`, `tools`, `risk_score`, `scopes`, graph paths, and policy records were not validated before diff logic consumed them. Malformed shapes could crash the CLI or be coerced into misleading diff data instead of failing closed.
4. A stored `capability_fingerprint` was trusted solely because it was 64 characters long. A tampered artifact could therefore present a fingerprint inconsistent with its capability list.
5. The CLI `diff` command did not normalize invalid/missing snapshot input into the existing invalid-input style of non-zero exit behavior.

## Fixes

- Added a dedicated bounded snapshot loader with a 16 MiB per-artifact byte limit, nesting-depth limit, and total JSON-node limit.
- Snapshot artifacts must be regular non-symlink files, valid UTF-8, standard JSON objects, and supported schema/capability-schema versions when those fields are present.
- Stable diff-consumed fields are shape-validated before use; malformed artifacts fail closed instead of being string-coerced or crashing later.
- Stored capability fingerprints must be hexadecimal and must match the fingerprint derived from the validated capability list.
- `agentcapdiff diff` now reports unsafe/invalid snapshot input and returns exit code 3 rather than emitting a traceback for rejected artifacts.
- Legacy valid snapshots that omit newer fields remain readable, and unknown additive top-level fields remain safely ignorable for the 1.x contract.

## Regression coverage

Permanent tests cover:

- per-artifact byte bounds;
- nesting and total-node bounds;
- parser recursion normalization;
- malformed stable field shapes;
- inconsistent fingerprints;
- unsupported snapshot schema versions;
- symlinked artifact rejection;
- CLI fail-closed exit behavior;
- backward readability of older snapshots plus additive unknown top-level fields.

## Compatibility and residual risk

The snapshot schema remains `1`, capability schema remains `"1"`, package/runtime version remains `1.0.0`, and valid legacy/additive 1.x artifacts preserve their documented behavior. The new rejection paths apply to malformed, unsupported, inconsistent, symlinked, or resource-excessive artifacts rather than redefining valid snapshot meaning.

Configured bounds reduce denial-of-service and artifact-confusion risk but do not prove an artifact is trustworthy or that an agent is safe at runtime. Snapshot diffing remains static and performs no target-code execution/import, endpoint probing, or credential use.
