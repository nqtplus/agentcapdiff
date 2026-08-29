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
      "adapter": "openai-agents",
      "source": "tools.json",
      "signal": "name/description matched: read[_ -]?file"
    }
  ],
  "confidence": "medium"
}
```

`id` is the normalized capability identity. Framework syntax is retained only as evidence and must not change the meaning of the normalized capability. `scope`, `evidence`, and `confidence` are separate first-class fields so uncertainty is visible instead of being hidden behind one score.

## Static adapter contract

AgentCapDiff remains a JSON/YAML static analyzer. An adapter recognizes a statically serialized tool shape; it does **not** import an SDK, execute decorators, instantiate tools, or run target code to discover runtime behavior.

| Adapter evidence | Static shape recognized |
| --- | --- |
| `mcp` | `name` + camel-case `inputSchema` |
| `openai` | nested `function.parameters`, or direct `type: function` + `parameters` |
| `openai-agents` | `name` + `params_json_schema` |
| `claude` | `name` + snake-case `input_schema` |
| `langchain` | `args_schema` with LangChain-style metadata, or `tool_call_schema` |
| `langgraph` | LangChain-compatible schema plus explicit static LangGraph provenance |
| `crewai` | `args_schema` with CrewAI-specific `result_as_answer` or explicit static CrewAI provenance |

Ambiguous `args_schema` input is still analyzed for capability and scope evidence, but its framework provenance stays `generic` and classification confidence stays lower. AgentCapDiff must not guess a framework merely to make coverage appear broader.

Adapters may add evidence but must not weaken normalized privilege meaning. Equivalent supported tool definitions must normalize to the same capability ID, risk class, policy decision, and conservative scope classification.

Capability inference does not rely only on a tool's display name and top-level description. Static input-schema titles/descriptions and a deliberately narrow set of security-relevant property/action signals are also reviewed. This prevents a benign-looking name from hiding an explicit schema such as `shellCommand`, `apiToken`, `path + content`, or `repository + operation=merge`.

Schema-only inference is intentionally conservative: it is recorded at `low` confidence unless independent name/description evidence also exists. Generic fields that are too ambiguous to establish an operation are not promoted into stronger claims merely to increase coverage; for example, a bare `url` parameter alone is not treated as proof of network access.

When the same `(tool name, source file)` is discovered through multiple serialized shapes, AgentCapDiff merges the static descriptions/schema branches instead of letting traversal order choose one record and silently discard the others. Conflicting adapter attribution becomes `generic`, preserving uncertainty while retaining the union of static capability/scope evidence.

If a framework exposes dynamic, incomplete, or ambiguous permissions, the adapter must preserve that uncertainty. In particular, unknown scope stays `unknown`; it must never be converted to `restricted` merely because a framework-specific field is missing or unsupported.

## Adapter conformance gate

The v0.3 conformance suite expresses equivalent filesystem and external-network tools through every supported static adapter shape and verifies that:

1. capability IDs and risk weights remain equivalent across adapters;
2. statically proven path/domain restrictions remain equivalent;
3. dynamic/unconstrained scope remains `unknown`;
4. adapter provenance is retained as evidence without changing capability identity;
5. an existing deny-policy decision cannot become weaker merely because the same privilege is represented by another framework;
6. ambiguous framework attribution remains generic instead of being guessed.

Post-v1.0 security regressions additionally cover schema-hidden high-risk signals and duplicate-shape collisions so a supported static representation cannot downgrade a dangerous capability simply by moving evidence out of the display name/description or by colliding on the same tool name/source.

This is a semantic conformance test, not a claim that every possible SDK object or runtime configuration is recognized.

## Confidence

The current classifier uses conservative qualitative confidence values: `low`, `medium`, or `high`. Recognized static adapter metadata with direct name/description evidence receives `medium` classification confidence; ambiguous/generic tool shapes and schema-only operational inference receive `low`. Confidence describes the evidence quality for the classification, not whether runtime behavior is safe.

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

## Security boundary and limitations

The schema represents static evidence only. It does not execute target code, contact discovered endpoints, validate runtime authorization, or prove that an agent is safe. Runtime permissions may differ from declared metadata, so unknown and low-confidence states must remain visible to reviewers.

Framework adapters only apply when corresponding tool metadata is present in scanned JSON/YAML. AgentCapDiff does not inspect Python/JavaScript object graphs or execute framework code to materialize schemas. Unsupported or runtime-generated shapes therefore remain outside positive adapter attribution rather than being silently labeled safe.
