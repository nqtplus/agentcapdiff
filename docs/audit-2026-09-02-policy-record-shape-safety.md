# Audit #36 — Policy record shape safety

## Scope

Harden direct-library `policy_to_record()` calls against malformed `Policy(...)` container shapes before machine-readable policy metadata is emitted.

## Finding

Audits #33 and #34 made the sealed-result producer and direct evaluator fail closed on malformed policy containers. `policy_to_record()` still serialized those values directly.

A type-invalid but iterable value such as `Policy(deny="shell.execute")` was therefore sortable and could be emitted as a list of individual characters. Enforcement would reject the same malformed policy, while the serializer could still publish a machine-readable record with a different apparent policy meaning.

## Remediation

- apply the existing effective-policy shape validator before policy serialization;
- reject malformed deny/review, threshold, allowlist, scope-constraint, unknown-scope, trust-boundary, suppression-container, and source-container shapes;
- preserve the existing policy record schema and field meanings for valid policy objects;
- preserve unambiguous direct-library collection variants already accepted by the evaluator and seal boundary.

## Regression coverage

Permanent tests cover:

- string deny rejection instead of character-wise serialization;
- malformed direct policy container rejection across security-relevant fields;
- unchanged machine-readable record structure for valid list/tuple/set/frozenset-compatible inputs.

## Security effect

The direct policy serializer can no longer emit a policy record from container shapes that the enforcement engine itself considers invalid. This removes a misleading machine-readable output path without changing valid scanner output.

## Residual boundary

This audit validates shape, not canonical identity representation. Direct policies using valid but non-canonical selector spellings may still serialize their supplied spelling while the evaluator canonicalizes effective identity. Binding serialized selector identity to evaluated identity should be reviewed separately because it changes direct-library record normalization semantics.

## Non-goals

This audit does not change policy precedence, selector canonicalization, suppression expiry semantics, capability inference, risk scoring, YAML syntax, snapshot schema, CLI syntax, package version, target-code execution, endpoint probing, credentials, or historical snapshot behavior.
