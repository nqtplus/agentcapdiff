# Threat Model

## Assets

- Reviewer understanding of what an AI agent can do
- Integrity of project capability policy
- CI results and security findings
- Developer workstations and CI runners executing AgentCapDiff

## Trust boundaries

AgentCapDiff consumes repository-controlled JSON/YAML as untrusted input. It must parse those files without executing them. It does not import target project code and does not execute discovered tools.

## Threats considered

1. **Capability expansion hidden in a code diff** — mitigated by normalized inventory and snapshot diffing.
2. **Over-broad tool names/descriptions** — surfaced through explainable rule matches; semantic scope analysis is future work.
3. **Policy weakening in the same PR** — currently visible in code review but not independently protected; baseline-policy comparison is planned.
4. **Malicious parser input** — YAML uses `safe_load`; target code is never imported.
5. **False assurance** — docs explicitly state that a clean scan is not proof of safety.

## Non-goals for v0.1

- Dynamic sandboxing
- Vulnerability exploitation
- Runtime authorization
- Prompt-injection detection
- Secret scanning
