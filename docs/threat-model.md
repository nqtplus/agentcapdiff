# Threat Model

## Security objective

AgentCapDiff should let reviewers inspect changes in agent capabilities **without creating a new reason to execute, trust, or expose data from the repository being scanned**.

A clean AgentCapDiff result is evidence about the static inputs it recognized. It is **not proof that an agent, tool implementation, dependency, prompt, or runtime environment is safe**.

AgentCapDiff 1.x treats the capability/policy semantics and documented machine-readable output contracts as stable security-relevant interfaces. Silent reinterpretation of those interfaces is itself a review concern; see `docs/stability-v1.0.md`.

## Assets

- Reviewer understanding of what an AI agent can do
- Integrity of project capability policy and snapshot evidence
- Integrity of stable JSON/SARIF/snapshot/diff contracts consumed by automation
- Integrity of explicitly requested local report/snapshot output files
- CI results and security findings
- Developer workstations and CI runners executing AgentCapDiff
- Local secrets and files that must remain outside the scan boundary
- Integrity and provenance of AgentCapDiff release artifacts
- Integrity of the public composite Action runtime and the caller workspace boundary

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

Local output paths are operator-selected authority and are never derived from scanned metadata. AgentCapDiff still treats the filesystem destination as a write boundary: report, diff, snapshot, and benchmark output reject symlinked/non-regular destinations and redirected parent paths. New contents are written and fsynced to a same-directory temporary regular file before atomic replacement, so an interrupted/failed write does not first truncate a valid existing output. POSIX parent traversal uses no-follow directory descriptors so a symlink swap cannot redirect the write to another filesystem tree.

GitHub CI and release workflows are a separate supply-chain trust boundary. External Actions are commit-SHA pinned; direct CI/release dependencies are reviewed exact pins; release publication uses least-privilege job permissions, checksums, an SPDX SBOM, attestations, and fail-closed immutable-release verification.

The public composite GitHub Action is also a consumer-side trust boundary. Action inputs are passed as environment data rather than interpolated into shell source. The wrapper confines scan/policy authority to `GITHUB_WORKSPACE`, requires a configured policy file to exist unless the caller explicitly supplies an empty policy input, and runs AgentCapDiff from its trusted Action source with caller-workspace import paths removed. Runtime dependencies are installed into a temporary isolated virtual environment from an exact SHA-256 wheel lock instead of mutating the caller Python environment. The Action currently supports GitHub Actions on Linux X64 with CPython 3.11-3.13 and fails closed outside that reviewed contract.

## Threats considered

1. **Capability expansion hidden in a code diff** — mitigated by normalized inventory, semantic scope evidence, capability graphs, and snapshot diffing.
2. **Over-broad or ambiguous tool metadata** — represented with separate evidence/confidence/scope; dynamic or unsupported scope remains unknown instead of safe.
3. **Policy weakening in the same PR** — effective-policy fingerprints and explicit policy-weakening warnings surface removed/relaxed controls.
4. **Malicious parser input** — YAML uses `safe_load`; discovery applies explicit resource bounds and cycle-aware traversal.
5. **Path/symlink escape** — symlinked scan roots/files are rejected, inherited-policy paths are confined, and resolved scan candidates must remain inside the root boundary.
6. **Resource exhaustion** — oversized, excessively deep, too numerous, or structurally pathological inputs fail closed with a non-zero CLI result when they cross configured safety limits.
7. **Output injection** — untrusted values rendered into reviewer-facing Markdown are destination-escaped; JSON/SARIF are structurally serialized and regression-tested.
8. **Output-path redirection or partial overwrite** — explicit output writes reject symlink/non-regular destinations and symlinked parents, use no-follow parent traversal where supported, and publish only with same-directory atomic replacement after the complete temporary file is fsynced. CLI output-path failures return a controlled non-zero result rather than silently following a link or exposing a partial report.
9. **False assurance** — benchmark metrics keep high-risk false negatives, parser failures, false positives, and unknowns visible rather than collapsing them into a single reassuring score.
10. **Release/dependency compromise** — Action/dependency pins, Dependabot review, SBOM/checksums/attestations, least-privilege publication, and immutable-release verification reduce silent supply-chain drift.
11. **Stable-contract drift** — v1.0 contract tests and project-state checks guard security-relevant capability/policy/output semantics from silent incompatible change; additive evolution must remain safely ignorable by older 1.x consumers.
12. **Composite Action input/runtime compromise** — untrusted Action inputs are not inserted into Bash source, Action paths cannot escape the caller workspace, configured policy absence fails closed, the caller interpreter environment is not modified, runtime wheels are hash-locked, and trusted Action source is imported without caller-workspace module shadowing.

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
- least-privilege GitHub workflow permissions around the composite Action
- a reviewed supported runner/Python environment for Action execution
- reviewed full commit SHA or reviewed verified immutable release references for AgentCapDiff itself

## Non-goals

- Dynamic sandboxing
- Vulnerability exploitation
- Runtime authorization
- Prompt-injection detection
- Secret scanning or secret collection
- Network vulnerability scanning or endpoint probing

## Residual risk

Static classification can miss capabilities hidden in implementation code, generated configuration, runtime composition, aliases, misleading descriptions, or unsupported frameworks. It can also over-classify benign tools. Release attestations establish recorded build provenance, not source-code correctness. Commit/version pinning prevents silent ref movement but cannot prevent a later-discovered compromise already present in a pinned dependency or Action. Compatibility regression tests cover documented contracts but cannot guarantee that every downstream consumer uses those contracts correctly. An adversary that already controls the destination directory with the same operating-system identity can still remove or rename output paths after AgentCapDiff returns; atomic/no-follow output handling prevents link-following and partial publication but is not a substitute for filesystem permissions or process isolation. The composite Action cannot reduce permissions granted by its caller or make other caller workflow steps safe; GitHub-hosted/self-hosted runner integrity, Python/venv/pip implementation integrity, network/package-index availability, and reviewed hash admission remain external trust roots.

These are documented limitations to measure and review, not conditions under which AgentCapDiff may claim an agent or release is intrinsically safe. See `docs/stability-v1.0.md`, `docs/v1.0-verification.md`, `docs/safety-benchmark.md`, `docs/security-review-v0.9.md`, `docs/release-integrity.md`, and `docs/audit-2026-08-29-composite-action-runtime.md`.
