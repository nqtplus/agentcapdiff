# Capability snapshots

AgentCapDiff snapshots are deterministic, machine-readable summaries of the statically inferred capability surface.

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

The fingerprint is **not** a content hash of the repository and is **not** a security signature. It is only a stable identifier for the normalized capability surface.

## Backward compatibility

The diff engine can read older schema-1 snapshots that do not contain `capability_fingerprint`; it derives the fingerprint from their `capabilities` list at read time.
