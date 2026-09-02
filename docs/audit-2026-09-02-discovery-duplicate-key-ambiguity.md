# Audit #40 — Discovery duplicate-key ambiguity

Date: 2026-09-02

## Finding

Discovery parsed JSON with the standard `json.loads()` behavior and YAML with `yaml.safe_load()`. Both paths can accept duplicate mapping/object keys with an effective last-key-wins interpretation.

At the discovery trust boundary this is security-relevant because duplicate keys can shadow the exact static evidence used to recognize and classify a tool: `name`, `description`, framework/type hints, schema fields, or nested schema properties. A repository could therefore present two conflicting values while capability inference only sees the parser-selected value.

Audit #39 made malformed explicitly selected files fail closed, but ordinary directory discovery intentionally remains tolerant of unrelated malformed documents. Duplicate-key ambiguity must not enter that tolerant skip path: silently skipping an ambiguous tool-definition document would still allow the ambiguity to erase security evidence.

## Remediation

Discovery now reuses the repository's duplicate-safe parsers:

- JSON uses `jsonio.loads_unique()` and rejects duplicate decoded object keys at every nesting depth;
- YAML uses `yamlio.safe_load_unique()` and rejects duplicate raw mapping keys before merge flattening;
- `yamlio` exposes `DuplicateYAMLMappingKeyError`, a `ConstructorError` subtype, so discovery can distinguish duplicate-key ambiguity from ordinary malformed YAML;
- JSON and YAML duplicate-key errors are converted to `DiscoveryLimitError` for both explicit-file and directory scans;
- ordinary malformed/unreadable documents encountered during directory traversal remain tolerant as established by Audit #39;
- one YAML merge key plus an explicit local override remains valid and keeps existing precedence semantics.

## Regression coverage

Permanent tests cover:

- explicit JSON duplicate keys;
- duplicate JSON keys encountered during directory discovery;
- duplicate keys nested inside an input schema;
- JSON keys that become duplicates only after Unicode escape decoding;
- duplicate YAML mapping keys during directory discovery;
- valid YAML merge plus explicit local override compatibility;
- controlled CLI directory-scan failure without traceback;
- the existing parser-recursion regression now targets the shared JSON parser seam without changing its semantics.

## Compatibility

This audit does not make all malformed directory documents fatal. It narrowly changes duplicate mapping/object keys from permissive/ambiguous input into a fail-closed discovery error.

Policy YAML behavior remains compatible because `DuplicateYAMLMappingKeyError` still subclasses PyYAML `ConstructorError`/`YAMLError`; existing policy error normalization therefore remains unchanged.

No capability IDs, adapter inference rules, risk weights, policy semantics, snapshot schema, CLI syntax, report schema, package version, target-code execution, endpoint probing, or credentials behavior changes.

## Residual boundary

Directory discovery still tolerates non-duplicate syntax/read failures for unrelated JSON/YAML documents. Detecting when a malformed directory document is itself security-relevant tool metadata remains a separate problem and should not be solved with filename-only heuristics without evidence.
