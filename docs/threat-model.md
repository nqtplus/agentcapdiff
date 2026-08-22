# Threat Model

## Security objective

AgentCapDiff should let reviewers inspect changes in agent capabilities **without creating a new reason to execute, trust, or expose data from the repository being scanned**.

A clean AgentCapDiff result is evidence about the static inputs it recognized. It is **not proof that an agent, tool implementation, dependency, prompt, or runtime environment is safe**.

## Assets

- Reviewer understanding of what an AI agent can do
- Integrity of project capability policy and snapshot evidence
- CI results and security findings
- Developer workstations and CI runners executing AgentCapDiff
- Local secrets and files that must remain outside the scan boundary

## Trust boundaries

AgentCapDiff treats repository-controlled JSON, YAML, paths, names, descriptions, and schemas as untrusted input.

The static scanner must not:

- import or execute target repository code
- invoke discovered tools
- resolve or contact discovered network endpoints
- follow repository symlinks to read data outside the intended scan tree
- construct arbitrary Python objects from YAML
- interpret an unknown/dynamic scope as restricted or safe

The scanner may read supported static tool-definition files within configured resource limits. Current discovery bounds include per-file bytes, total parsed bytes, candidate document count, nesting depth, and structured-node count.

## Threats considered

1. **Capability expansion hidden in a code diff** — mitigated by normalized inventory and snapshot diffing.
2. **Over-broad tool names/descriptions** — surfaced through explainable rule matches; semantic scope analysis remains incomplete until v0.2 scope work lands.
3. **Policy weakening in the same PR** — currently visible in normal code review but not independently protected; policy-diff enforcement is planned.
4. **Malicious parser input** — YAML uses `safe_load`; discovery applies explicit resource bounds and cycle-aware traversal.
5. **Path/symlink escape** — symlinked scan inputs are rejected rather than followed.
6. **Resource exhaustion** — oversized, excessively deep, too numerous, or structurally pathological inputs fail closed with a non-zero CLI result.
7. **Output injection** — untrusted values rendered into reviewer-facing output must be escaped for the destination format; regressions here are security-relevant when they can alter review meaning or cross a boundary.
8. **False assurance** — user-facing docs explicitly distinguish static evidence, unknowns, and runtime safety.

## Unknown and low-confidence behavior

AgentCapDiff intentionally prefers uncertainty over an unsafe claim. When a permission or scope cannot be established statically, the intended state is **unknown**, not safe. A reviewer should treat unknown scope as requiring further review or runtime controls.

## Defense in depth expected from users

AgentCapDiff is only one review layer. Production users should still use:

- ordinary code review
- runtime authorization and least-privilege credentials
- sandboxing or isolation when executing untrusted tools
- secret isolation and short-lived credentials
- dependency and supply-chain controls
- environment-specific allowlists and network controls where appropriate

## Non-goals

- Dynamic sandboxing
- Vulnerability exploitation
- Runtime authorization
- Prompt-injection detection
- Secret scanning or secret collection
- Network vulnerability scanning or endpoint probing

## Residual risk

Static classification can miss capabilities hidden in implementation code, generated configuration, runtime composition, aliases, misleading descriptions, or unsupported frameworks. It can also over-classify benign tools. These are expected limitations and should be measured rather than hidden as the benchmark corpus matures.
