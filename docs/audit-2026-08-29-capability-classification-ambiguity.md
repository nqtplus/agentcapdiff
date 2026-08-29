# Capability-classification ambiguity audit — 2026-08-29

## Scope

This is one coherent post-v1.0 audit pass covering adversarial static capability classification:

- capability evidence hidden outside a tool's display name/description;
- cross-framework representation changes that could downgrade the same privilege;
- duplicate tool-name/source collisions that could discard stronger static evidence;
- conservative handling of ambiguous schema signals and false-positive pressure;
- preservation of the no-target-execution/no-discovered-network boundary.

Baseline main before this audit:

`962053ac681c578a33f7b612e9d3c2c50c6a25d7`

The product remains v1.0.0. This audit does not change the universal capability schema version, risk weights, public package version, JSON/SARIF shape, or the static-only execution boundary.

## Finding 1 — dangerous operation evidence could be hidden in the input schema

The classifier primarily matched capability rules against `tool.name + tool.description`. Supported adapters already preserved each static input schema for scope inference, but capability identity did not inspect that schema.

A benign-looking tool such as `task_worker` / `Process a task` with an explicit `shellCommand` input therefore carried static evidence of command execution while producing no `shell.execute` capability. The same downgrade could be reproduced across supported adapter shapes because the weakness was downstream of adapter extraction.

### Remediation

Capability inference now also reviews a deliberately narrow static schema signal set:

- schema titles/descriptions are matched against the existing capability rules;
- explicit command/shell/script properties preserve `shell.execute`;
- secret/credential/token/password properties preserve `secrets.access`;
- path + payload or path + explicit mutation action preserves `filesystem.write`;
- path-only static evidence can preserve the weaker `filesystem.read` claim when no write signal is present;
- repository + explicit mutation action can preserve `github.write`;
- recipient/message combinations can preserve `email.send`;
- only stronger network-oriented property names such as endpoints/request URLs are used as schema-only network signals; a bare `url` field alone is not promoted into proof of network access.

Schema-only operational inference is intentionally `low` confidence. Direct name/description evidence on a recognized static adapter retains the existing `medium` confidence behavior.

Permanent conformance coverage expresses a schema-hidden shell capability through every supported adapter and requires the same `shell.execute` risk identity without guessing runtime behavior.

## Finding 2 — duplicate `(tool name, source)` records used last-writer-wins deduplication

Discovery can encounter the same logical tool through more than one serialized shape in one source file. The previous deduplication dictionary keyed only by `(name, source)` and assigned one `ToolRecord`, so traversal order selected the surviving record.

A benign generic representation could therefore replace a second representation that carried stronger schema/provenance evidence, or vice versa. This made classification depend on serialization/traversal order rather than the union of available static evidence.

### Remediation

Duplicate records are now merged conservatively:

- all non-empty descriptions are retained deterministically;
- all distinct in-memory schema branches are preserved under a synthetic container that existing static walkers can traverse;
- conflicting adapter attribution becomes `generic` instead of selecting one framework;
- no schema branch is discarded merely because another record has the same tool name/source.

The normalized public tool record remains one logical tool. The change affects only how internal static evidence is combined before capability/scope inference.

## Benchmark and regression gates

This audit adds:

- a permanent high-risk benchmark fixture whose shell capability exists only as `inputSchema.properties.shellCommand`;
- cross-framework conformance for that schema-hidden shell capability;
- unit regression coverage for camel-case secret input, path+payload write inference, explicit filesystem/GitHub mutation actions, deliberate non-classification of a bare URL parameter, and duplicate-shape evidence merging.

The benchmark still requires zero high-risk false negatives and zero parser failures. The new case ensures future changes cannot silently restore the name/description-only shell blind spot.

## Residual boundary

Static schema labels are evidence, not runtime proof. Tool implementations may perform more, less, or different work than their declared metadata. AgentCapDiff therefore keeps schema-only classification at low confidence and does not infer broad capabilities from generic fields merely to maximize recall.

Unsupported/runtime-generated behavior can still be outside positive static classification. Reviewers must continue to treat missing or low-confidence evidence conservatively; a clean scan is not proof of safety.

No target repository code is imported or executed, no discovered endpoint is contacted, and no credentials are used by these changes.
