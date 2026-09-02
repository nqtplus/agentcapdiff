# Audit #41 — Discovery ignore-scope binding

Date: 2026-09-02

## Finding

Discovery skipped supported JSON/YAML candidates whenever any component in `path.parts` matched an ignored directory name such as `build`, `dist`, `node_modules`, `.tox`, or `.git`.

`path.parts` is the full path, not the path relative to the caller-selected scan root. As a result, an explicitly selected root located inside an ignored-named directory could have every supported input skipped. For example, scanning `/repo/build/agent` caused each candidate path to contain the `build` component and could return a misleading empty/clean capability result. An explicitly selected supported file below `node_modules` was affected for the same reason.

Ignored directories are a traversal-scope optimization for descendants of a selected directory. They must not silently override the caller's explicit scan boundary.

## Remediation

Discovery now:

- resolves each candidate against the established scan-root boundary first;
- computes the candidate path relative to that boundary;
- applies `IGNORED_DIRS` only to parent components inside the relative candidate path;
- therefore scans a root whose own name or ancestry matches an ignored directory;
- therefore scans an explicitly selected supported file even when its ancestry contains an ignored directory name;
- continues to skip ignored directories nested inside a directory scan root.

The existing root-escape check, symlink handling, parser hardening, document/byte/node budgets, and static-only behavior are unchanged.

## Regression coverage

Permanent tests cover:

- explicitly selected directory root named `build`;
- selected root below a `dist` ancestor;
- explicitly selected supported file below `node_modules`;
- unchanged ignoring of `node_modules` and `build` descendants inside a scan root;
- ordinary nested non-ignored discovery.

## Compatibility

Default repository scans continue to ignore the same descendant directory names. The only behavior change is that ignore names outside the caller-selected scan boundary no longer suppress explicitly selected inputs.

No capability IDs, adapter inference, risk weights, policy semantics, snapshot schema, CLI syntax, report schema, package version, target-code execution, endpoint probing, or credentials behavior changes.

## Residual boundary

An explicitly selected regular file with an unsupported suffix is still skipped by the supported-suffix filter and can produce an empty result. That explicit-input eligibility case remains separate from ignored-directory scope and should be reviewed independently.
