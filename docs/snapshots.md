# Capability snapshots

AgentCapDiff snapshots are deterministic, machine-readable summaries of the statically inferred capability surface. Snapshot files supplied to `diff` are untrusted artifacts: parsing and validation are fail-closed before their contents are used to produce a review result.

## Capability fingerprint

Each new snapshot includes `capability_fingerprint`, a lowercase SHA-256 digest. The digest is computed from a canonical JSON object containing only:

```json
{"schema":1,"capabilities":["sorted","unique","capability.ids"]}
```

Canonicalization rules:

1. capability IDs are deduplicated and sorted lexicographically;
2. JSON object keys are sorted;
3. JSON uses compact separators and ASCII-safe encoding;
4. tool names, source paths, findings, risk score, timestamps, and checkout metadata are excluded.

This means identical normalized capability surfaces produce the same fingerprint across machines and checkout paths. Adding or removing a capability changes the fingerprint.

The fingerprint is **not** a content hash of the repository and is **not** a security signature. It is only a stable identifier for the normalized capability surface. A matching fingerprint therefore cannot make contradictory auxiliary fields trustworthy by itself.

## Semantic consistency across snapshot fields

Current snapshots contain additive evidence beyond the legacy capability list. When that evidence is present, AgentCapDiff verifies that the security-relevant fields agree before diffing:

- `capability_records` must describe the same normalized capability IDs as `capabilities`;
- tools referenced by capability records must be present in the top-level `tools` inventory when that inventory is present;
- `risk_score` must equal the risk score derived from the detailed capability records;
- static `scopes` must agree with the scope evidence in capability records;
- capability-graph nodes, edges and possible paths must agree with the graph deterministically rebuilt from capability records;
- scope, graph and finding references cannot point to capabilities or tools excluded by top-level inventories when those inventories are present;
- `max_severity` must agree with the included findings when the findings list is present;
- conflicting duplicate security identities fail closed rather than allowing record order to choose a winner.

A contradiction is treated as an unsafe snapshot artifact, not as an ordinary capability change. The CLI therefore refuses to render a normal diff from contradictory evidence.

These checks do not turn a snapshot into a cryptographically authenticated artifact. They establish only internal semantic consistency among the static evidence fields that the snapshot itself contains.

## Additive compatibility

The 1.x reader keeps the existing additive compatibility model. Unknown future fields are ignored when the known security-relevant projection remains valid. Older schema-1 snapshots may omit newer fields such as `capability_records`, `scopes`, policy metadata or the capability graph; AgentCapDiff does not fabricate missing evidence merely to satisfy a newer schema.

Cross-field checks are applied only when the corresponding evidence exists. For example, a legacy snapshot containing only `capabilities`, `tools` and `risk_score` remains readable, while a newer snapshot that includes `capability_records` cannot make those records disagree with the top-level capability inventory.

## Backward compatibility

The diff engine can read older schema-1 snapshots that do not contain `capability_fingerprint`; it derives the fingerprint from their `capabilities` list at read time. Valid additive unknown fields remain ignorable. Unsupported schema versions, malformed structures, inconsistent fingerprints, contradictory security evidence, symlinked files, or artifacts exceeding parser safety bounds fail closed.
