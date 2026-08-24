# Changelog

All notable changes will be documented here.

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
- Escaping for untrusted values rendered into Markdown summaries, including scope evidence
- Regression coverage verifies static scans do not execute target instructions or contact discovered endpoints

## [0.1.0] - 2026-08-21

### Added
- Explainable capability inference for common agent powers
- OpenAI-style and MCP-like tool discovery
- YAML policy with deny/review/score controls
- Text, JSON, and SARIF reports
- Capability snapshots and diffs
- Composite GitHub Action and CI workflows
