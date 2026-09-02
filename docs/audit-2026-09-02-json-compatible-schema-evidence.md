# Audit #23 — JSON-compatible schema evidence

## Scope

This audit checks whether scanner-sealed tool schema evidence can be canonicalized safely when metadata is loaded from YAML as well as JSON.

Audit #22 deliberately added `ToolRecord.input_schema` to the private semantic fingerprint so sealed capabilities are bound to the exact evidence used for inference. This audit focuses on the hostile-input boundary created by canonicalizing that newly bound schema evidence.

## Finding

`yaml.safe_load()` is safe from arbitrary object construction, but YAML still has native scalar/container types that do not belong to JSON. Examples include timestamps loaded as `datetime.date` or `datetime.datetime`, binary values loaded as `bytes`, sets, non-string mapping keys, and non-finite numeric values.

The Audit #22 fingerprint used `json.dumps()` over `input_schema`. For unsupported YAML-native values, Python can raise `TypeError` during sealing. The CLI normalizes scanner `ValueError` failures into its documented invalid-input exit path, but it did not catch this `TypeError`. A hostile but parseable YAML tool definition could therefore crash the scanner instead of failing closed with a controlled diagnostic.

Non-finite floats were a related canonicalization gap: Python's JSON encoder accepts NaN and infinity by default even though they are not valid JSON values.

## Remediation

Scanner-sealed results now validate every non-null `ToolRecord.input_schema` as strict JSON-compatible data before capability re-inference or fingerprinting:

- mappings must use string keys;
- sequences must be lists;
- scalar values must be JSON primitives;
- floating-point values must be finite;
- YAML/Python-native values such as dates, bytes, sets, and other unsupported objects are rejected;
- cyclic mappings/sequences are rejected;
- excessive recursive nesting is normalized to `ScanResultConsistencyError` rather than escaping as a raw recursion failure.

Canonical JSON generation also uses `allow_nan=False` as a second fail-closed guard.

The validator does not stringify, coerce, or silently drop unsupported evidence. Invalid schema evidence is rejected so capability inference cannot proceed from a representation that differs from the data later bound by the semantic fingerprint.

## Permanent regressions

Tests cover:

- YAML-native date, binary, and set values being rejected at seal time;
- NaN, positive infinity, and negative infinity being rejected;
- non-string schema mapping keys being rejected;
- JSON-compatible date-like strings remaining valid;
- a schema that was valid when sealed but is later mutated to a YAML-native date being rejected before serialization;
- CLI scanning of a parseable YAML tool schema containing an unquoted timestamp returning exit code 3 with a controlled invalid-input diagnostic rather than an uncaught exception.

## Compatibility

Valid JSON-compatible tool schemas are unchanged. Capability IDs, risk weights, scope inference, policy precedence, public JSON/SARIF/snapshot formats, the no-schema-leak contract, and package version remain unchanged at `1.0.0`.

Unsealed manual `ScanResult` objects retain their existing 1.x permissive serialization behavior. The stricter requirement applies to scanner-sealed semantic evidence, where deterministic canonicalization is part of the security guarantee.

## Security effect

The sealed evidence chain can now be canonicalized deterministically across supported JSON/YAML inputs without relying on Python's behavior for non-JSON YAML values. Parseable hostile YAML can no longer use a schema-native scalar to escape the scanner's controlled invalid-input path.

## Residual boundaries

This remains a static metadata scanner, not a YAML schema repair tool. Unsupported YAML-native values inside tool input schemas are intentionally rejected rather than coerced. Deliberate hostile concurrent mutation and private-attribute manipulation remain outside the in-process object-sandbox claim documented by Audits #21 and #22.
