# Universal capability schema

AgentCapDiff v0.3 introduces a small framework-neutral capability record. The goal is to preserve security meaning when equivalent tools are expressed through different agent frameworks.

Current schema version: `1`.

## Record shape

```json
{
  "schema_version": "1",
  "id": "filesystem.read",
  "tool": "read_file",
  "risk": 10,
  "reason": "Can read local files.",
  "source": "tools.json",
  "scope": {
    "kind": "restricted",
    "values": ["./reports/**"],
    "reason": "Static schema limits the path to an explicit value."
  },
  "evidence": [
    {
      "adapter": "openai",
      "source": "tools.json",
      "signal": "name/description matched: read[_ -]?file"
    }
  ],
  "confidence": "medium"
}
```

`id` is the normalized capability identity. Framework syntax is retained only as evidence and must not change the meaning of the normalized capability. `scope`, `evidence`, and `confidence` are separate first-class fields so uncertainty is visible instead of being hidden behind one score.

## Adapter contract

Adapters may add evidence but must not weaken the normalized privilege meaning. Equivalent MCP and OpenAI-style tool definitions must normalize to the same capability ID, risk class, and conservative scope classification.

If a framework exposes dynamic, incomplete, or ambiguous permissions, the adapter must preserve that uncertainty. In particular, unknown scope stays `unknown`; it must never be converted to `restricted` merely because a framework-specific field is missing or unsupported.

## Confidence

The current classifier uses conservative qualitative confidence values: `low`, `medium`, or `high`. Recognized OpenAI and MCP static tool metadata currently receives `medium` classification confidence; generic tool shapes receive `low`. Confidence describes the evidence quality for the classification, not whether runtime behavior is safe.

## Canonicalization

`canonical_capabilities_json()` sorts records deterministically by normalized capability ID, tool name, and source, then serializes JSON with stable key ordering and separators. This is intended for adapter conformance tests and reproducible downstream processing.

The existing snapshot `schema: 1`, capability ID list, and capability fingerprint remain backward-readable. v0.3 adds `capability_schema_version` and `capability_records` rather than removing the v0.2 fields.

## Schema evolution rules

1. A schema version must be explicit and versioned independently from the package version.
2. Additive fields may be introduced without changing normalized privilege meaning.
3. Removing or reinterpreting a security-relevant field requires a new schema version.
4. Older snapshot capability IDs and fingerprints remain readable where possible.
5. An adapter must never silently drop a privilege, broaden a known restriction into a reassuring value, or turn `unknown` into safe/restricted.
6. Unsupported schema versions fail explicitly rather than being guessed.

## Security boundary

The schema represents static evidence only. It does not execute target code, contact discovered endpoints, validate runtime authorization, or prove that an agent is safe. Runtime permissions may differ from declared metadata, so unknown and low-confidence states must remain visible to reviewers.
