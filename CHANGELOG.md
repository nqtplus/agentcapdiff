# Changelog

All notable changes will be documented here.

## [1.0.1] - 2026-09-02

### Fixed
- Release publication no longer calls GitHub's repository-administration-only `immutable-releases` settings endpoint with the least-privilege Actions `GITHUB_TOKEN`.
- Immutable-release acceptance remains fail-closed: publication must still return `isImmutable=true`, and exact-source workflow-owned draft/mutable release state is cleaned up without deleting or moving the source tag.

### Security
- The failed `v1.0.0` publication attempt stopped before artifact build, attestations, or GitHub Release creation; no `v1.0.0` release assets were published.
- The existing `v1.0.0` tag remains pinned to `f5ff28757aa1f1678483267e6c57e747cd04d9ed` as an audit-trail source identity and is not moved or reused.
- The repaired production publication candidate is `1.0.1`, preserving the v1.0 compatibility contract while fixing only the release-control authorization mismatch.

## [1.0.0] - 2026-09-02

### Added
- Stable 1.x compatibility contract for normalized capability records and policy semantics
- Stable JSON scan and SARIF 2.1.0 machine-readable output guarantees with regression tests
- v1.0 release-verification record mapping framework conformance, semantic-scope, capability-path, benchmark, fuzz/security, and supply-chain gates to repository evidence
- Dedicated v1.0 contract tests for capability schema versioning, JSON top-level output, SARIF rule/source structure, and explicit unknown-scope semantics

### Changed
- Package/runtime version finalized at `1.0.0` and project maturity marked Production/Stable only after the v1.0 release gate is satisfied
- README and ROADMAP now expose the v1.0 stable compatibility and safety contract
- 1.x compatibility guidance makes breaking security-semantic reinterpretation a major/schema decision rather than a silent change
- Final pre-publication verification was refreshed after the post-gate security-hardening series and before creation of the first `v1.0.0` production tag

### Security
- Static-only safety invariants remain unchanged: no target-code execution/import, discovered-endpoint probing, or credential use; UNKNOWN remains uncertainty rather than SAFE
- Stable release verification requires Python 3.11/3.12/3.13 CI, full pytest/Ruff, benchmark and release-integrity regression gates, CodeQL, self-policy, PR capability diff, project-state consistency, and no known unresolved critical/high repository security issue
- Pre-publication hardening added sealed-result semantic consistency, strict effective-policy validation, temporary-suppression expiry enforcement, duplicate-key-safe policy/snapshot/discovery parsing, and fail-closed explicit discovery input handling
- Discovery hardening prevents malformed explicit inputs, ambiguous duplicate mapping keys, ignored-ancestor path names, and unsupported explicit file suffixes from silently producing misleading clean results
- Production use continues to require a reviewed full commit SHA or a reviewed verified immutable release tag instead of a floating branch reference

## [0.9.0] - 2026-08-26

### Added
- Reproducible static safety benchmark with explicit high-risk false-negative, parser-failure, false-positive, and unknown reporting
- Release-integrity checker that rejects floating GitHub Action refs, unsafe workflow triggers/permissions, unpinned direct CI/build dependencies, and incomplete release controls
- SPDX 2.3 SBOM generation for built release artifacts and declared runtime dependencies
- Tag-triggered release workflow with SHA-256 checksums, build provenance attestation, SBOM attestation, release-tag/version validation, and immutable-release verification
- Weekly Dependabot review flow for Python dependencies and GitHub Actions
- Security-focused review of parser, path, output, PR-CI, and release trust boundaries
- Regression coverage for symlinked directory scan roots and release/SBOM integrity

### Changed
- Package/runtime version finalized at `0.9.0`
- Build backend, runtime dependency, developer test/lint tools, and CI/release direct dependencies use reviewed exact pins for the v0.9 release line
- All third-party GitHub Actions in repository workflows are pinned to full commit SHAs
- Production guidance prefers reviewed full commit SHAs or verified immutable release tags instead of floating branches

### Security
- Release workflow starts from `permissions: {}` and grants only job-local permissions required for validation, CodeQL, attestations, and publication
- A production release is accepted only if GitHub reports `isImmutable=true`; otherwise the workflow fails closed and attempts to remove the mutable release/tag
- Scanner discovery now explicitly rejects a symlinked directory supplied as the scan root and verifies resolved candidate paths remain inside the root boundary
- Compromise/revocation guidance requires a new fixed version rather than silently replacing artifacts or moving an affected release tag

## [0.5.0] - 2026-08-25

### Added
- Per-tool capability allowlists and static filesystem/network scope constraints
- Explicit `unknown_scope` handling with conservative `review` default
- Trust-boundary annotations carried into effective policy records and review output
- Deterministic local policy inheritance with ordered parents and child precedence
- Temporary policy suppressions requiring a non-empty reason and ISO expiry date
- Effective policy snapshots, policy fingerprints, and PR policy-weakening warnings
- Review warnings for removed denies/review requirements, raised risk thresholds, relaxed unknown handling, expanded tool/scope allowlists, new or extended suppressions, and removed trust-boundary annotations
- Backwards-readability tests for legacy policies and snapshots without policy metadata

### Changed
- CLI and composite GitHub Action default to `fail-on: medium`
- Invalid, escaping, cyclic, over-deep, malformed-suppression, or expired-suppression policy input fails closed
- PR Markdown now surfaces policy changes independently from capability changes

### Security
- Inherited policy files are restricted to the root policy directory and symlinked policy files are rejected
- Expired suppressions cannot silently remain active; malformed or expired suppression configuration invalidates the policy
- Trust-boundary annotations are review context only and are not represented as proof of runtime isolation
- Unknown scope remains uncertainty rather than evidence of safety
- Policy evaluation remains static and deterministic with no target-code execution/import, endpoint probing, credential use, or runtime enforcement claims

## [0.4.0] - 2026-08-24

### Added
- Separately versioned deterministic capability graph derived from normalized static capabilities
- Conservative possible data-egress, credential-egress, and source-control/supply-chain mutation path rules
- Scope-aware path severity with confidence kept as an independent signal
- Additive capability-graph snapshot records with backward compatibility for older snapshots
- Snapshot diffing and PR Markdown for newly introduced possible capability paths
- Positive, negative, ambiguous-scope, deterministic, backward-compatibility, and Markdown regression tests
- Public capability-graph schema and interpretation documentation

### Security
- Capability paths are explicitly evidence-backed possibilities, not claims of runtime reachability or exploitability
- Unknown scope never becomes a reassuring restriction; it lowers confidence and cannot reduce scope-sensitive severity
- Graph analysis remains static: no target-code execution/import, endpoint probing, credential use/collection, or dynamic exploitation

## [0.3.0] - 2026-08-23

### Added
- Versioned universal capability schema with first-class `scope`, `evidence`, and `confidence`
- Backward-readable snapshot capability records while preserving v0.2 capability IDs/fingerprints
- Static adapter provenance for MCP, OpenAI API-style tools, OpenAI Agents SDK, Claude, LangChain/LangGraph-compatible metadata, and CrewAI-style metadata
- Deterministic cross-framework adapter conformance suite for equivalent filesystem/network privileges
- Conformance checks that dynamic scope remains `unknown` and framework representation cannot weaken deny-policy decisions

### Changed
- Ambiguous `args_schema` metadata remains generic/low-confidence instead of guessing framework provenance
- Adapter documentation now states explicit static-only support boundaries and schema-evolution rules
- Project/version metadata finalized at `0.3.0` only after v0.3 implementation gates passed

### Security
- Framework adapters remain fully static and do not import/execute target SDK code or contact discovered endpoints
- Unknown, runtime-generated, unsupported, or ambiguous behavior is never promoted to known-safe/restricted solely for framework coverage

## [0.2.0] - 2026-08-22

### Added
- PR-native base/head capability comparison workflow
- Markdown capability diff output for GitHub review summaries
- Risk-score context and policy findings in snapshots/diffs
- Stable SHA-256 capability fingerprints with backward-compatible derivation
- Static filesystem scope evidence with restricted, broad, and unknown states
- Static network scope evidence for exact domains, wildcard domains, URL prefixes, broad and unknown destinations
- Semantic scope-change and proven-expansion reporting in snapshot diffs
- Sanitized MCP fixture corpus with parameterized classification tests
- Deterministic fuzz/property hardening and security regression tests
- Project-state consistency workflow for roadmap/version drift

### Security
- Bounded untrusted JSON/YAML input by file bytes, total bytes, document count, nesting depth, and structured nodes
- Cycle-aware traversal, symlink rejection, fail-closed CLI behavior for unsafe inputs
- Conservative traversal/dynamic scope handling: ambiguous scope remains unknown
