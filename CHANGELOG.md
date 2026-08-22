# Changelog

All notable changes will be documented here.

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
