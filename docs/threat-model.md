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
- Integrity and provenance of AgentCapDiff release artifacts

## Trust boundaries

AgentCapDiff treats repository-controlled JSON, YAML, paths, names, descriptions, and schemas as untrusted input.

The static scanner must not:

- import or execute target repository code
- invoke discovered tools
- resolve or contact discovered network endpoints
- follow repository symlinks to read data outside the intended scan tree
- construct arbitrary Python objects from YAML
- interpret an unknown/dynamic scope as restricted or safe

The scanner may read supported static tool-definition files within configured resource limits. Discovery bounds include per-file bytes, total parsed bytes, candidate document count, nesting depth, and structured-node count. Symlinked scan roots/files are rejected and candidate paths are checked against the resolved scan-root boundary.

GitHub CI and release workflows are a separate supply-chain trust boundary. External Actions are commit-SHA pinned; direct CI/release dependencies are reviewed exact pins; release publication uses least-privilege job permissions, checksums, an SPDX SBOM, attestations, and fail-closed immutable-release verification.

## Threats considered

1. **Capability expansion hidden in a code diff** — mitigated by normalized inventory, semantic scope evidence, capability graphs, and snapshot diffing.
2. **Over-broad or ambiguous tool metadata** — represented with separate evidence/confidence/scope; dynamic or unsupported scope remains unknown instead of safe.
3. **Policy weakening in the same PR** — effective-policy fingerprints and explicit policy-weakening warnings surface removed/relaxed controls.
4. **Malicious parser input** — YAML uses `safe_load`; discovery applies explicit resource bounds and cycle-aware traversal.
5. **Path/symlink escape** — symlinked scan roots/files are rejected, inherited-policy paths are confined, and resolved scan candidates must remain inside the root boundary.
6. **Resource exhaustion** — oversized, excessively deep, too numerous, or structurally pathological inputs fail closed with a non-zero CLI result when they cross configured safety limits.
7. **Output injection** — untrusted values rendered into reviewer-facing Markdown are destination-escaped; JSON/SARIF are structurally serialized and regression-tested.
8. **False assurance** — benchmark metrics keep high-risk false negatives, parser failures, false positives, and unknowns visible rather than collapsing them into a single reassuring score.
9. **Release/dependency compromise** — Action/dependency pins, Dependabot review, SBOM/checksums/attestations, least-privilege publication, and immutable-release verification reduce silent supply-chain drift.

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
- reviewed full commit SHA or verified immutable release references for AgentCapDiff itself

## Non-goals

- Dynamic sandboxing
- Vulnerability exploitation
- Runtime authorization
- Prompt-injection detection
- Secret scanning or secret collection
- Network vulnerability scanning or endpoint probing

## Residual risk

Static classification can miss capabilities hidden in implementation code, generated configuration, runtime composition, aliases, misleading descriptions, or unsupported frameworks. It can also over-classify benign tools. Release attestations establish recorded build provenance, not source-code correctness. Commit/version pinning prevents silent ref movement but cannot prevent a later-discovered compromise already present in a pinned dependency or Action.

These are documented limitations to measure and review, not conditions under which AgentCapDiff may claim an agent or release is intrinsically safe. See `docs/safety-benchmark.md`, `docs/security-review-v0.9.md`, and `docs/release-integrity.md`.
