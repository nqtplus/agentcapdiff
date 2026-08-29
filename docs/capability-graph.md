# Capability graph and compositional risk

AgentCapDiff v0.4 introduces a separately versioned **static capability graph**. The graph is derived only from already-inferred capability records; it never executes target code, imports target SDKs, probes endpoints, resolves runtime reachability, or uses credentials.

Current graph schema version: `1`.

## Graph shape

```json
{
  "schema_version": "1",
  "nodes": [
    {
      "capability": "secrets.access",
      "tools": ["read_secret"],
      "max_risk": 35
    },
    {
      "capability": "network.external",
      "tools": ["fetch_url"],
      "max_risk": 15
    }
  ],
  "edges": [
    {
      "source": "secrets.access",
      "target": "network.external",
      "relation": "credential-to-network-egress"
    }
  ],
  "paths": [
    {
      "id": "possible.secrets_network_exfiltration",
      "title": "Possible credential/data exfiltration path",
      "severity": "HIGH",
      "confidence": "low",
      "capabilities": ["secrets.access", "network.external"],
      "tools": ["fetch_url", "read_secret"],
      "evidence": ["..."],
      "message": "...possible path only; runtime reachability and exploitability are not established."
    }
  ]
}
```

The graph is additive snapshot data. Older snapshots without `capability_graph` remain readable.

## Deterministic path rules

The initial rule set detects the following capability combinations:

| Path ID | Required capabilities | Interpretation |
| --- | --- | --- |
| `possible.secrets_network_exfiltration` | `secrets.access` + `network.external` | possible credential/data exfiltration |
| `possible.filesystem_email_egress` | `filesystem.read` + `email.send` | possible file-to-message data egress |
| `possible.secrets_email_egress` | `secrets.access` + `email.send` | possible credential-to-message egress |
| `possible.github_shell_supply_chain_mutation` | `github.write` + `shell.execute` | possible source-control/supply-chain mutation |

A path exists only when every required normalized capability is present in the static scan result. Absence of a path does not prove that no runtime path exists.

Multiple contributing capability records never create duplicate rule paths. Path evidence is normalized as a deterministic, deduplicated set of review strings: repeated identical records collapse, scope values are sorted/deduplicated for evidence rendering, and evidence order does not depend on discovery order. Distinct evidence with the same tool/source remains distinct when its scope or confidence differs, so uncertainty is not silently discarded.

## Severity and confidence are separate

Severity represents potential impact of the capability combination. Confidence represents how strongly static metadata supports the classification.

For scope-sensitive paths, any scope that is not proven `restricted` keeps/escalates severity conservatively. A known `broad` scope can increase severity without lowering confidence merely because it is broad; `unknown` or an unrecognized scope state lowers confidence because AgentCapDiff cannot establish the boundary from static evidence. Restricted scope may keep a path at a lower severity, but the path remains visible.

This separation prevents `unknown` from becoming a reassuring safety signal.

## Evidence

Each path records the normalized capabilities, contributing tools, scope state, and capability confidence. Evidence is deterministic and review-oriented. It does not include secrets, live credential values, network responses, or dynamically executed observations.

Tool display names remain static evidence rather than a claim of runtime object identity. Alias-looking names may therefore both appear in the tool list; they do not create additional copies of the same deterministic path rule. AgentCapDiff does not fuzzy-match arbitrary Unicode/confusable runtime tool identities in the graph layer.

## PR review behavior

Snapshots include the graph and path records. Snapshot diffing keeps the existing `paths_added`/`paths_removed` behavior and additionally exposes additive `path_changes` and `path_escalations` records for an existing path ID whose security-relevant evidence changed.

A path escalation is review-required when, for the same path ID:

- severity increases;
- confidence decreases;
- the path's required capability sequence changes; or
- the contributing tool set expands.

This prevents a path that already existed in the base snapshot from silently becoming materially more dangerous while escaping the “new path” section. The Markdown PR summary renders changed paths separately and marks risk/uncertainty increases as review-required while continuing to state that runtime reachability/exploitability is not established.

Tool/evidence ordering-only differences are normalized before comparison so they do not fabricate path changes.

Snapshot path IDs are security-relevant identities. When a `capability_graph.paths` array is present, every path must have a non-empty ID and duplicate IDs fail closed. Diffing never resolves duplicate IDs by “last item wins.” Legacy snapshots that omit the graph entirely remain readable.

## Safety and interpretation

Capability paths are **possible/evidence-backed paths**, not exploit findings. They must not be described as confirmed exfiltration, confirmed compromise, or confirmed exploitability unless separate evidence genuinely establishes that conclusion.

AgentCapDiff remains static and low-risk:

- no target-code execution or import
- no dynamic exploitation
- no endpoint probing or DNS resolution
- no credential access or collection
- no runtime graph traversal
- unknown scope remains unknown

A clean graph is evidence about recognized static capability combinations, not proof that an agent is safe.
