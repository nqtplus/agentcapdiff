# Audit #42 — Explicit discovery suffix eligibility

Date: 2026-09-02

## Finding

Discovery supports static JSON/YAML inputs (`.json`, `.yaml`, `.yml`). The candidate loop skips every other suffix, which is appropriate during directory traversal. The same suffix filter also applied when the caller explicitly selected one regular file.

As a result, commands such as `agentcapdiff scan tools.toml`, `agentcapdiff scan tools.txt`, or `agentcapdiff scan tools.json.bak` silently skipped the selected artifact and could produce a misleading empty/clean capability result.

An explicit file path is an asserted discovery target. If that target is outside the supported static input formats, the scanner must report that it cannot evaluate the selected artifact rather than treating the artifact as evidence of no capabilities.

## Remediation

`discover_tools()` now validates explicit-file eligibility before candidate traversal:

- explicitly selected files must use `.json`, `.yaml`, or `.yml`;
- suffix matching remains case-insensitive, so `.JSON`, `.YAML`, and `.YML` remain valid;
- unsupported explicit-file suffixes raise `DiscoveryLimitError` with the supported formats;
- directory scans continue to skip unsupported extensions exactly as before;
- CLI scan/snapshot normalize the controlled error to exit code 3;
- snapshot output is not created for an unsupported explicit target.

## Regression coverage

Permanent tests cover:

- `.toml`, `.txt`, `.json.bak`, and extensionless explicit files;
- case-insensitive supported `.JSON` input;
- unchanged directory tolerance for unsupported extensions;
- controlled CLI scan failure without traceback;
- snapshot failure without writing an artifact.

## Compatibility

No directory-discovery format expansion is introduced. AgentCapDiff still recognizes static JSON/YAML tool definitions only. This audit tightens only the contract for a caller-selected regular file whose format AgentCapDiff cannot inspect.

No capability IDs, parser behavior for supported formats, adapter inference, risk weights, policy semantics, snapshot schema, CLI syntax, report schema, package version, target-code execution, endpoint probing, or credentials behavior changes.
