# Static scope-inference ambiguity audit — 2026-08-29

## Scope

This is one coherent post-v1.0 audit pass covering adversarial filesystem/network scope inference:

- JSON Schema annotation-vs-constraint semantics;
- `allOf` / `anyOf` / `oneOf`, negative and unused schema branches;
- alternate/camelCase path and network field names;
- contradictory or incomplete static evidence;
- restricted-to-broad and restricted-to-unknown review semantics;
- preservation of the static-only, no-target-execution/no-discovered-network boundary.

Baseline main before this audit:

`cec503947e9fd0761fe0ff68b955f0e078cffcf1`

The product remains v1.0.0. This pass does not change capability IDs, risk weights, the universal capability schema version, JSON/SARIF top-level contracts, policy precedence, or the meaning of the existing machine-readable `scope_expansions` field.

## Finding 1 — JSON Schema annotations could be mistaken for authorization bounds

The previous scope walker collected `const`, `enum`, `default`, and `examples` alike. `default` and `examples` are descriptive annotations; they do not constrain what a caller may submit.

A tool with `path: {type: string, default: "./reports/**"}` could therefore be labeled `restricted` even though arbitrary paths remained valid. The same false reassurance applied to network examples.

### Remediation

Only applied finite `const`/`enum` evidence can establish a finite static scope. Defaults/examples no longer count as restriction evidence. If a relevant path/destination field is present but lacks a proven finite bound, scope remains `unknown`.

## Finding 2 — semantic-blind traversal could turn alternatives, negatives, or unused definitions into positive restrictions

The prior generic recursive walker descended into every dictionary/list without respecting JSON Schema control semantics. It could collect a finite value from one `anyOf`/`oneOf` branch while another branch remained unconstrained, read an enum below `not` as if it were allowed, or treat a path inside unused `$defs` as an active authorization boundary.

### Remediation

Scope evidence now uses a conservative schema-aware walk:

- `allOf` can retain an applied finite upper bound;
- `anyOf`/`oneOf` require every possible scope-carrying branch to be finitely bounded before `restricted` is claimed;
- negative `not` evidence never becomes a positive restriction;
- unused `$defs`/`definitions` are ignored as inactive definitions;
- root/field `$ref`, conditional/optional alternatives, and unconstrained relevant properties remain `unknown` when AgentCapDiff cannot prove the bound;
- common camelCase/hyphenated aliases are normalized before matching scope fields.

This favors an explicit false-unknown over a false-restricted result.

## Finding 3 — loss of proven restriction was visually easy to miss

`scope_expansions` intentionally represents proven widening, so `restricted -> unknown` was correctly not classified as a proven expansion. However, the Markdown PR review rendered it as an ordinary scope change with no stronger review marker.

That can hide a meaningful evidence regression: the scanner no longer has proof of the finite boundary it previously had.

### Remediation

The existing `scope_expansions` semantics remain unchanged for 1.x. A dedicated semantic helper recognizes `restricted -> unknown` as increased scope uncertainty, and Markdown PR review now marks it:

`REVIEW REQUIRED — SCOPE UNCERTAINTY INCREASED`

The wording deliberately does not claim runtime broadening; it says only that finite static restriction evidence was lost.

## Regression coverage

Permanent tests cover:

- `default` and `examples` not establishing restricted scope;
- mixed bounded/unbounded `anyOf` becoming unknown;
- fully finite `oneOf` preserving a conservative union;
- `not` and unused `$defs` not creating positive scope evidence;
- finite `allOf` plus a neutral branch remaining restricted;
- camelCase scope aliases;
- unconstrained schema overriding a reassuring restricted description;
- restricted-to-unknown remaining distinct from proven expansion while receiving an explicit Markdown review warning.

## Residual boundary

JSON Schema can express constraints more richly than AgentCapDiff's static scope model. Unsupported references, dynamic relationships, custom validators, runtime authorization, or framework-specific semantics can therefore remain `unknown`. That is intentional: `unknown` is uncertainty, not safety.

No target repository code is imported or executed, no discovered endpoint is contacted, and no credentials are used by this audit or its remediation.
