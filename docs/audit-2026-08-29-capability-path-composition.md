# Capability graph/path composition audit — 2026-08-29

## Scope

This is one coherent post-v1.0 audit pass covering the capability graph and possible-path review layer after the classifier, scope, and policy hardening passes:

- path identity and deterministic evidence ordering;
- duplicate/aliased contributing tools and duplicate capability evidence;
- uncertainty propagation into path severity/confidence;
- existing-path changes across snapshots;
- untrusted snapshot path-ID integrity;
- conservative wording that does not overclaim runtime reachability/exploitability.

Baseline main before this audit:

`596c318f7352a06218c3a56a778b20727c7ceaa7`

The product remains v1.0.0. This audit does not change capability IDs, risk weights, path rule IDs, graph schema version, policy precedence, SARIF version, or the static-only trust boundary.

## Finding 1 — existing path risk could worsen without a path-level diff signal

Snapshot diffing keyed possible paths only by `id`. If a path already existed in both base and head, a change such as:

- `MEDIUM` → `HIGH` severity;
- `high` → `low` confidence because scope became unknown;
- expansion of contributing tools; or
- a changed capability sequence under the same path identity

was not represented in `paths_added`/`paths_removed`. Scope changes could provide partial nearby evidence, but the path-level risk change itself was easy to miss and tool/evidence changes could occur without a new capability ID.

### Remediation

Diffing keeps the existing path-added/removed contract and adds two backward-compatible fields:

- `path_changes`: normalized before/after records for an existing path ID whose record changed;
- `path_escalations`: the subset that requires review because severity increased, confidence decreased, capabilities changed, or the contributing tool set expanded.

Markdown PR review now renders a **Changed possible capability paths** section and marks escalations as **REVIEW REQUIRED — PATH RISK/UNCERTAINTY INCREASED**. The wording still explicitly states that runtime reachability/exploitability is not established.

## Finding 2 — path evidence ordering could depend on discovery order

Path evidence was sorted only by `(tool, source)` while the rendered evidence also contains scope and confidence. Two records with the same tool/source but different scope/confidence therefore had an equal sort key, so reversing input discovery order could reverse evidence output. Exact duplicate records could also repeat identical evidence strings.

This weakened deterministic snapshots and made evidence identity noisier than necessary.

### Remediation

Path evidence is now a deterministic deduplicated set of rendered static observations:

- identical evidence collapses;
- scope values are sorted and deduplicated before rendering;
- the final evidence list is globally sorted;
- distinct scope/confidence observations remain distinct.

Duplicate/alias-looking tools still do not create duplicate rule paths. Tool display names remain evidence rather than a claim of runtime object identity.

## Finding 3 — untrusted snapshots allowed ambiguous duplicate path IDs

Snapshot validation type-checked capability path records but did not require a non-empty path ID or reject duplicate path IDs. Later diff code built a dictionary keyed by ID, which meant duplicate IDs could be resolved implicitly by item order (`last item wins`).

Snapshot files are explicitly untrusted artifacts, so security-relevant identity must not depend on attacker-controlled ordering.

### Remediation

When `capability_graph.paths` exists:

- every path must have a non-empty string `id`;
- duplicate path IDs fail closed with `SnapshotArtifactError`;
- legacy snapshots that omit `capability_graph` remain readable.

Diffing therefore never silently resolves duplicate path identities by order.

## Finding 4 — unrecognized scope state should remain conservative in path aggregation

The normal scanner emits only `restricted`, `broad`, or `unknown`, but the graph layer can also be called directly. An unrecognized scope state previously did not match either `broad` or `unknown`, so scope-sensitive severity/confidence aggregation could accidentally treat malformed direct input more favorably than explicit uncertainty.

### Remediation

For scope-sensitive path rules:

- only proven `restricted` avoids the conservative HIGH severity escalation;
- known `broad` remains high impact without automatically reducing classification confidence;
- `unknown` or any unrecognized scope state lowers path confidence to `low`.

This preserves the invariant that uncertainty cannot become a reassuring signal.

## Regression coverage

Permanent tests cover:

- path graph output remaining deterministic when capability input order reverses;
- duplicate evidence collapsing deterministically;
- scope-value evidence normalization;
- mixed restricted/unknown evidence remaining HIGH/low-confidence;
- unrecognized scope states treated conservatively;
- alias-looking tool names not duplicating a deterministic rule path;
- existing path severity/confidence escalation surfaced without a new path ID;
- contributing-tool expansion surfaced even when no new normalized capability ID appears;
- input reordering not fabricating a path change;
- duplicate and empty snapshot path IDs failing closed;
- old snapshots without graph data remaining readable.

Existing capability graph schema stays `1`. Existing `paths_added`/`paths_removed` keys remain unchanged; `path_changes` and `path_escalations` are additive 1.x diff fields that older readers may ignore safely.

## Residual boundary

The capability graph is a static compositional-risk model, not a runtime reachability graph. It cannot prove that two tools are connected at runtime, that credentials flow between them, or that a possible path is exploitable. Tool aliases/confusables are not fuzzy-resolved into runtime identity, and evidence changes can require human interpretation even when severity/confidence do not worsen.

No target repository code is imported or executed by this audit, no discovered endpoint is contacted, and no credentials are requested or used.
