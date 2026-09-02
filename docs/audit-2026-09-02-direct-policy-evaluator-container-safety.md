# Audit #34 — Direct policy evaluator container safety

## Scope

Harden direct-library calls to `evaluate_policy()` so malformed `Policy(...)` container shapes cannot be silently interpreted by Python iteration semantics and weaken enforcement.

## Finding

The YAML loader normalizes policy containers, and Audit #33 added equivalent validation before `ScanResult.seal()`. Direct callers of `evaluate_policy()` still bypassed that producer-boundary validation.

For example, `Policy(deny="shell.execute")` is type-invalid but iterable. The evaluator previously iterated the string character-by-character while canonicalizing deny selectors, so the intended `shell.execute` deny rule was not represented. This is fail-open behavior for malformed direct-library policy input.

Other malformed container shapes could similarly be coerced by iteration or fail with incidental Python exceptions rather than a controlled policy-validation error.

## Remediation

- validate effective policy container shapes at the start of `evaluate_policy()`;
- reject malformed direct-library policy input before any canonicalization or finding generation;
- preserve unambiguous direct collection variants (`set`, `frozenset`, `list`, `tuple`) for string collections and list/tuple for suppression/source sequences;
- preserve existing selector canonicalization, suppression expiry checks, policy precedence, and valid policy behavior;
- return controlled `ValueError` failures for malformed direct evaluator input.

## Regression coverage

Permanent tests cover:

- `Policy(deny="shell.execute")` rejected instead of being iterated character-by-character;
- malformed review, threshold, allowlist, scope-constraint, unknown-scope, trust-boundary, suppression, and source shapes;
- accepted list/tuple/set/frozenset variants still evaluate normally;
- nested unambiguous collection variants remain compatible.

## Security effect

Malformed direct-library policy input can no longer bypass stable 1.x policy meaning through Python's generic iteration behavior. Direct evaluation now fails closed before security-relevant canonicalization occurs.

## Residual boundary

Audit #33 and Audit #34 intentionally enforce equivalent invariants at two internal boundaries. Consolidating those validators into one shared internal helper is a maintainability improvement, not required to close this fail-open path, and should be reviewed separately to avoid coupling a security fix to refactoring.

## Non-goals

This audit does not change capability inference, risk scoring, policy precedence, YAML syntax, public output schemas, CLI syntax, package version, target-code execution, endpoint probing, credentials, or historical snapshot behavior.
