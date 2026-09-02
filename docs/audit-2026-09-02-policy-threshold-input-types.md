# Audit #27 — Raw policy threshold input types

## Scope

This audit reviews the raw YAML-to-Policy conversion for `max_risk_score`, before the effective-policy seal invariant added by Audit #24.

## Finding

`load_policy()` previously converted the raw value with:

```python
int(raw.get("max_risk_score", 60))
```

That conversion blurred the security-policy input contract in two ways.

First, hostile but parseable YAML values such as `null`, a list, or a mapping can make `int(...)` raise `TypeError`. The CLI's invalid-input path is designed around controlled `ValueError` failures, so a raw `TypeError` could escape instead of producing the normal fail-closed exit code.

Second, values with the wrong type could be silently coerced before the Audit #24 effective-policy check saw them. Examples include `60.5` becoming `60`, `"60"` becoming `60`, and YAML boolean `true` becoming integer `1`. Once coerced, the downstream seal invariant could no longer distinguish the original ambiguous policy input from an intentionally authored integer.

## Remediation

Raw policy loading now uses a dedicated `_load_max_risk_score()` validator instead of `int(...)` coercion.

The file value must be:

- an integer;
- not a boolean;
- between 0 and 100 inclusive.

The validator returns the original integer unchanged and raises `ValueError` for all other types or ranges. No string, float, boolean, null, sequence, or mapping coercion is performed.

Audit #24's `seal_scan_result()` effective-policy validation remains in place as defense in depth for policies constructed programmatically rather than loaded from YAML.

## Permanent regressions

Tests cover raw policy values:

- `null`;
- list;
- mapping;
- float;
- quoted numeric string;
- boolean;
- negative integer;
- integer above 100;
- valid boundary values 0 and 100.

CLI regressions verify that a `null` threshold fails through exit code 3 without an uncaught `TypeError`, and that `snapshot` with an invalid sequence threshold does not create an output artifact.

## Security effect

The author-visible YAML value and the effective aggregate-risk threshold now have the same type and value. Invalid policy types cannot be converted into a different valid security control, and hostile parseable values cannot escape the CLI's controlled invalid-input path through `TypeError`.

## Compatibility

Valid integer thresholds from 0 through 100 are unchanged. Policy precedence, capability rules, risk weights, scope semantics, public JSON/SARIF/snapshot formats, and package version remain unchanged at `1.0.0`.

Policies that previously relied on implicit numeric coercion are now rejected. That coercion was not a safe stable policy contract because it made the effective security value differ from the authored YAML type/value.

## Residual boundary

General discovery metadata parsing remains separate. Discovery intentionally scans many unrelated repository files and tolerates malformed documents, so applying strict duplicate/type rules there requires a dedicated completeness and denial-of-service compatibility analysis rather than reusing policy fail-closed semantics mechanically.
