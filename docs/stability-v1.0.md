# v1.0 stability contract

AgentCapDiff 1.0 is a stability and safety milestone. It does not expand the scanner into runtime execution or exploitation. The stable contract covers recognized static inputs, normalized capability/policy meaning, machine-readable output, and conservative review semantics.

## Compatibility guarantees

### Universal capability schema

The v1.0 stable capability schema remains `schema_version: "1"`.

For the 1.x release line:

- normalized capability IDs keep their existing security meaning;
- `scope.kind` remains one of `restricted`, `broad`, or `unknown`;
- `evidence` and `confidence` remain separate from severity/risk;
- additive fields may be introduced only when older readers can safely ignore them;
- removing or reinterpreting a security-relevant field requires a new schema version;
- unsupported or dynamic permissions remain explicit uncertainty and are never promoted to safe/restricted;
- legacy capability fingerprints continue to represent sorted normalized capability IDs only.

### Policy contract

The legacy `deny`, `require_review`, and `max_risk_score` fields remain supported. v0.5 fields (`allow_by_tool`, `scope_constraints`, `unknown_scope`, `trust_boundaries`, deterministic local `extends`, and expiring `suppressions`) remain additive for 1.x.

Policy precedence is stable: deny -> per-tool allowlist -> scope/unknown handling -> review requirement -> risk threshold -> explicit valid temporary suppression. Malformed/expired suppressions and unsafe inheritance fail closed.

A 1.x change that weakens these semantics requires explicit migration documentation and a major-version/schema decision rather than a silent reinterpretation.

## Stable machine-readable output

### JSON scan output

The top-level JSON scan object contains these stable keys:

- `risk_score`
- `max_severity`
- `tools`
- `capabilities`
- `capability_graph`
- `policy`
- `findings`

Existing keys are not removed or repurposed within 1.x. Additive keys are allowed when older consumers can ignore them safely.

### SARIF

SARIF output remains SARIF `2.1.0`, with one AgentCapDiff driver run. Findings retain `ruleId`, SARIF `level`, `message.text`, and a source `locations` entry. Rule IDs are security-relevant identifiers and must not be silently reused for different meanings.

### Snapshots and diffs

Existing snapshot schema/fingerprint fields remain backward-readable. Machine-readable diffs continue to expose capability/tool additions/removals, risk delta, scope changes/expansions, capability-path changes, policy-change state, and policy-weakening warnings where the corresponding evidence exists.

Snapshot files supplied to `diff` are treated as untrusted artifacts. Valid legacy snapshots that omit newer fields remain readable, and additive unknown top-level fields remain ignorable within the 1.x contract. Malformed, unsupported-schema, inconsistent-fingerprint, symlinked, excessively large, or excessively complex snapshot artifacts fail closed rather than being coerced into a potentially misleading diff.

## Framework conformance

The stable static adapter contract covers serialized metadata for MCP, OpenAI API tools, OpenAI Agents SDK, Claude tools, LangChain/LangGraph-compatible metadata, and CrewAI-style metadata. CI conformance tests verify equivalent filesystem/network privileges normalize consistently, dynamic scope remains unknown, and changing framework representation cannot weaken an explicit deny decision.

This is static serialized-metadata support only. AgentCapDiff does not import SDKs, instantiate tools, run decorators, inspect live object graphs, or execute target code.

## Semantic scope and capability paths

Filesystem/network scope regressions remain covered by restricted, broad, dynamic/unknown, traversal, and scope-expansion tests. Unknown scope is uncertainty, not safety.

Capability graph findings are evidence-backed *possible* paths. Review output must state that runtime reachability/exploitability is not established. A path finding must never be rewritten as proof of exploitation without new evidence and a separately reviewed product/security decision.

## Safety and release gates

The 1.0 release gate requires:

- reproducible committed benchmark with no regression in high-risk false negatives or parser failures;
- deterministic fuzz/input-hardening and parser/path/output security regression suites green;
- CI on Python 3.11/3.12/3.13, CodeQL, AgentCapDiff self-policy, PR capability diff, project-state consistency, and release-integrity checks green;
- no known unresolved critical/high security issue in the repository tracker at release time;
- current threat model, limitations, security reporting, supported-version policy, and release verification guidance;
- production guidance based on reviewed full commit SHAs or verified immutable release tags.

A green static scan or benchmark is evidence about the covered corpus and recognized metadata. It is not proof that an agent is safe at runtime.
