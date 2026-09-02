# Audit #39 — Explicit discovery input fail-closed

Date: 2026-09-02

## Finding

`discover_tools()` intentionally tolerates malformed or unreadable JSON/YAML documents found while scanning a directory because repositories can contain unrelated data files. The same exception path also applied when the scan root itself was one explicitly selected supported JSON/YAML file.

That meant a command such as `agentcapdiff scan tools.json` could receive malformed JSON, invalid YAML, or invalid UTF-8 and silently treat the selected file as if it contained no tools. A malformed tool-definition artifact could therefore produce a misleading clean/zero-capability result instead of a controlled failure.

## Remediation

The discovery layer now distinguishes an explicitly selected file from documents encountered during directory traversal:

- parse/read failures for the explicit supported file fail closed with `DiscoveryLimitError`;
- malformed/unreadable documents encountered inside a directory remain tolerant and are skipped as before;
- existing resource-limit, recursion, symlink, and root-boundary failures remain fail-closed;
- CLI scan/snapshot convert the controlled discovery error into exit code 3;
- snapshot output is not written after an explicit parse failure.

## Regression coverage

Permanent tests cover:

- malformed explicit JSON;
- malformed explicit YAML;
- invalid UTF-8 in an explicit JSON input;
- unchanged directory-scan tolerance when an unrelated malformed document is present beside a valid tool definition;
- controlled CLI scan failure without a traceback;
- snapshot failure without creating the requested artifact.

## Compatibility

Directory discovery behavior is intentionally unchanged. This audit only tightens the trust boundary when the caller explicitly selects a supported JSON/YAML input file and that selected artifact cannot be parsed/read safely.

No capability IDs, adapter inference, risk weights, policy semantics, snapshot schema, CLI syntax, report schema, package version, target-code execution, endpoint probing, or credentials behavior changes.

## Residual boundary

Duplicate mapping keys remain a separate parser-ambiguity question. A future audit should distinguish discovery-sensitive duplicate keys from unrelated repository data before changing directory-scan tolerance.
