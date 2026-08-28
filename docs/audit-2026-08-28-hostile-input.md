# Audit 2026-08-28 — hostile input and resource bounds

Scope: one post-v1.0 audit pass covering parser/path hostile-input handling, resource bounds, and the static no-network/no-execution invariant.

## Findings

1. Discovery bounded supported document count but did not bound the total number of filesystem entries traversed before filtering supported JSON/YAML files. A repository with very large irrelevant trees could therefore consume unbounded traversal work before a document limit applied.
2. Deep JSON/YAML could raise parser-level `RecursionError` before the post-parse structured-depth guard, bypassing the normal `DiscoveryLimitError` failure path.
3. Repository policy YAML (including inherited local policies) used `yaml.safe_load`, path confinement, cycle detection, and inheritance-depth limits, but did not have explicit per-file/aggregate byte, aggregate-file, structured-depth, or structured-node budgets. Malformed YAML could also escape the CLI's normal invalid-input handling instead of returning the documented non-zero invalid-input result.

These are denial-of-service/fail-closed robustness gaps. The audit found no path that imports or executes target repository code, probes discovered endpoints, or performs network access because of scanned metadata.

## Fixes

- Discovery now bounds total filesystem entries visited in addition to supported document count and existing byte/depth/node limits.
- Parser-level recursion failures are converted into actionable `DiscoveryLimitError` failures.
- Policy loading now bounds per-file bytes, aggregate parsed bytes, aggregate inherited file loads, structured nesting depth, and structured node count.
- Malformed, invalid-UTF-8, unreadable, or parser-recursive policy input is normalized to `ValueError`, so the CLI fails closed through its existing invalid-input exit path.
- Existing path confinement, symlink rejection, local-only inheritance, `yaml.safe_load`, and static scanner behavior remain in force.

## Regression coverage

Permanent tests cover:

- deeply nested JSON failing through the discovery limit error path;
- oversized repository traversal failing before unbounded enumeration;
- malformed policy YAML producing CLI exit code 3 rather than an uncaught parser exception;
- oversized and excessively deep policy structures;
- aggregate inherited-policy file budgeting;
- the existing no-network regression for discovered URLs and no-execution fuzz/property coverage.

## Compatibility

This hardening does not change capability IDs, policy semantics for valid bounded inputs, JSON/SARIF/snapshot/diff contracts, or package version. AgentCapDiff remains `1.0.0`; the changes are fail-closed safety hardening within the v1 stable contract.
