# Snapshot semantic consistency audit — 2026-08-29

## Scope

This is one coherent post-v1.0 audit pass of untrusted snapshot artifacts used by `agentcapdiff diff`. It covers semantic consistency between:

- `capabilities` and `capability_records`;
- top-level `tools` and tool identities referenced by detailed evidence;
- `risk_score` and detailed capability risk;
- `scopes` and capability-record scope evidence;
- capability graph nodes/edges/paths and the detailed capability surface;
- `findings` and their capability/tool references;
- `max_severity` and the included findings;
- the existing capability fingerprint and the capability list.

Baseline main before this audit:

`15d9cef5ca5ed6a80e78616843daaee837e144c2`

The product remains v1.0.0. The snapshot schema remains 1 and valid legacy additive-read compatibility is preserved.

## Finding 1 — field-level validation did not establish cross-field agreement

The snapshot loader already bounded file size/structure, used strict JSON parsing, rejected malformed stable field types and inconsistent capability fingerprints, and rejected ambiguous capability-path identity. Those controls validated individual fields but did not require independent security-relevant fields to describe the same static state.

A crafted snapshot could therefore keep a valid `capabilities` list and matching fingerprint while supplying contradictory detailed records, scope evidence, graph records or findings. Diff rendering could then combine mutually inconsistent claims from one artifact.

### Remediation

Snapshot validation now performs an additional semantic-consistency pass after structural and fingerprint validation. Contradictions raise `SnapshotArtifactError` and the CLI fails closed instead of rendering an ordinary diff.

## Finding 2 — detailed capability records were not validated as a security source

`capability_records` are used as detailed evidence but were not previously validated by the artifact loader. Invalid or conflicting detailed records could coexist with a valid top-level capability list.

### Remediation

When `capability_records` are present:

- stable schema version, identity, risk, scope, evidence and confidence fields are validated before conservative parsing;
- the normalized capability-ID set must equal top-level `capabilities` when that field is present;
- capability-record tool identities must exist in top-level `tools` when that inventory is present;
- conflicting records sharing the same `(capability, tool, source)` identity fail closed;
- `risk_score` must equal the score derived from detailed records.

## Finding 3 — scope and graph evidence could contradict the detailed capability surface

A snapshot could contain scope records or graph paths that do not follow from the detailed capability records, including references to absent capabilities/tools or altered graph severity/evidence.

### Remediation

When detailed records exist, AgentCapDiff deterministically derives the expected scope records and capability graph from them and compares only the known 1.x security-relevant projection. A mismatch fails closed.

Even without detailed records, scope/graph references cannot point outside top-level capability/tool inventories when those inventories are explicitly present, including when they are empty.

Unknown additive graph/path fields remain ignorable if the known projection is consistent.

## Finding 4 — finding summary could contradict finding evidence

A crafted snapshot could advertise a reassuring `max_severity` while including a more severe finding, or attach findings to capabilities/tools excluded by explicit inventories.

### Remediation

When findings are present:

- referenced capability/tool identities must exist in explicit top-level inventories;
- `max_severity`, when present, must equal the maximum included finding severity.

The absence of a findings list in a legacy snapshot does not cause AgentCapDiff to fabricate findings or infer a historical severity.

## Compatibility rule

The hardening is evidence-conditional. Older schema-1 snapshots that omit newer additive evidence remain readable. Unknown future fields are ignored when known semantics remain internally consistent. The reader does not require a legacy artifact to contain information that did not exist when it was written.

This preserves the 1.x additive compatibility contract while preventing a newer, richer snapshot from using contradictory redundant fields as separate sources of truth.

## Safety boundary

Semantic consistency is not authenticity and is not runtime proof. An internally consistent malicious snapshot may still contain fabricated static claims if it did not come from a trusted workflow or verified artifact channel. Existing provenance, repository review, and release-integrity controls remain separate trust layers.

This audit does not execute or import target repository code, probe discovered endpoints, access credentials, or perform dynamic exploitation.
