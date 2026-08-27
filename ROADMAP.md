# Roadmap

AgentCapDiff is being developed as a **safe, framework-neutral capability change layer for AI agents** — not as another generic vulnerability scanner.

The roadmap is ordered by two priorities:

1. **Differentiation:** make agent capability changes understandable across frameworks, scopes, and dangerous capability combinations.
2. **User safety:** scanning untrusted repositories must not create a new execution, data-exposure, supply-chain, or false-confidence risk.

## Product direction

AgentCapDiff should become the equivalent of a **semantic Git diff for agent powers**:

- normalize capabilities from different agent frameworks into one model
- show how permission scope expands or contracts across a PR
- explain evidence and uncertainty instead of hiding it behind one risk score
- detect dangerous combinations of otherwise ordinary capabilities
- remain fully static: no target-code execution, credential use, or network probing

### What should make AgentCapDiff different

1. **Universal capability schema** — one versioned model across MCP, OpenAI Agents, Claude tools, LangGraph/LangChain, CrewAI, and future adapters.
2. **Semantic scope diff** — detect changes such as `./reports/** -> /**` or `api.example.com -> arbitrary network`, not only `filesystem.write` or `network.external`.
3. **Compositional risk paths** — identify combinations such as `secrets.access + network.external` as a possible exfiltration path with explainable evidence.
4. **Review-first output** — optimize for PR review, deterministic snapshots, machine-readable evidence, and conservative human-readable summaries.
5. **Safety by construction** — untrusted input is bounded, unknown permissions are never labeled safe, and the scanner does not execute the thing it is scanning.

## Non-negotiable safety invariants

These rules apply to every release and adapter:

- **Never execute or import target repository code during static analysis.**
- **Never make network requests because of discovered tool definitions or endpoints.**
- Treat JSON, YAML, paths, names, descriptions, and schemas as **untrusted input**.
- Bound parsing by file size, nesting depth, document count, and total work to reduce denial-of-service risk.
- Use safe parsing only; no arbitrary YAML/object construction.
- Treat dynamic or ambiguous capability scope as **unknown**, never implicitly safe.
- Keep **severity, confidence, evidence, and scope** separate so uncertainty is visible.
- Escape untrusted values before rendering Markdown, SARIF, logs, or other structured output.
- Do not collect secrets or sensitive repository content beyond what is required for local static classification.
- CI and GitHub Actions must use least-privilege permissions.
- Production guidance must prefer immutable commit/release pins over floating refs such as `@main`.
- A clean scan is **evidence, not proof that an agent is safe**.

## v0.1 — Explainable capability inventory ✅

- [x] OpenAI-style tool discovery
- [x] MCP-like tool discovery
- [x] Initial capability taxonomy
- [x] Policy-as-code
- [x] JSON/text/SARIF output
- [x] Capability snapshots and diffs
- [x] Composite GitHub Action

## v0.2 — Semantic scope + safety foundation ✅

Goal: make capability changes more precise while hardening AgentCapDiff itself against hostile input.

- [x] Baseline snapshots from the default branch
- [x] Markdown PR summary
- [x] Stable capability fingerprint
- [x] Path-aware filesystem scope analysis — #5
- [x] Domain-aware network scope analysis — #6
- [x] Real-world sanitized MCP fixture corpus — #8
- [x] Untrusted-input hardening, resource limits, fuzz/property tests — #10
- [x] Explicit safety limitations and trust model — #15

### v0.2 release gate

- malformed or oversized fixtures fail safely
- no target-code execution or input-triggered network access
- scope inference distinguishes restricted, broad, and unknown
- security regression tests cover parser, path, and output-injection classes

## v0.3 — Universal capability schema ✅

Goal: establish the main interoperability moat instead of growing framework-specific scanners.

- [x] Versioned universal capability schema — #11
- [x] First-class `scope`, `evidence`, and `confidence`
- [x] MCP adapter conformance
- [x] OpenAI Agents SDK adapter
- [x] Claude tool-schema adapter
- [x] LangGraph/LangChain adapter
- [x] CrewAI adapter
- [x] Adapter conformance suite that detects lost or weakened privilege information

### v0.3 release gate

- adapters normalize equivalent powers consistently
- unsupported/dynamic behavior stays explicitly unknown
- schema evolution rules preserve backward readability
- adding a framework cannot silently weaken an existing policy decision

## v0.4 — Capability graph and compositional risk ✅

Goal: detect security-relevant **paths between capabilities**, not just isolated flags.

- [x] Versioned capability graph model — #12
- [x] Possible data-exfiltration paths
- [x] Possible supply-chain mutation paths
- [x] Credential + egress combinations
- [x] Scope-aware path severity
- [x] Conservative PR explanations with evidence and confidence

### v0.4 safety rule

AgentCapDiff must report these as **possible/evidence-backed paths**, not claim runtime exploitability unless that conclusion is actually supported. No dynamic exploitation, probing, credential use, or target execution is allowed.

## v0.5 — Policy maturity and safe review UX ✅

Goal: let teams express least privilege without creating dangerous false confidence or easy bypasses.

- [x] Capability allowlists by tool — #22
- [x] Scope constraints — #22
- [x] Trust-boundary annotations — #22
- [x] Policy inheritance with deterministic precedence — #22
- [x] Suppressions that require reason + expiry — #22
- [x] Explicit `unknown` handling policy — #22
- [x] Policy-weakening diff warnings — #22
- [x] Safe defaults for CI failure thresholds — #22

### v0.5 release gate

- policy weakening is visible in PR review
- suppression cannot silently become permanent
- ambiguous permissions cannot pass as known-safe by default
- backwards compatibility is tested for policy/schema changes

## v0.9 — Measured safety and release integrity ✅

Goal: prove that releases are becoming safer and reduce the chance that AgentCapDiff itself becomes a supply-chain risk.

- [x] Reproducible safety benchmark — #13
- [x] High-risk false-negative regression gate — #13
- [x] False-positive and unknown-rate reporting — #13
- [x] SBOM and release provenance — #14
- [x] Least-privilege release workflow — #14
- [x] Immutable tagged releases and production pinning guidance — #14
- [x] Dependency/GitHub Action integrity checks — #14
- [x] Security-focused review of parser, path, output, and CI trust boundaries

### v0.9 release gate

- high-risk false-negative and parser-failure benchmark gates pass; false positives and unknowns remain separately visible
- all third-party GitHub Actions are pinned to full commit SHAs and dependency/Action updates are reviewed through Dependabot PRs
- release artifacts include SHA-256 checksums, an SPDX SBOM, build provenance, and SBOM attestations
- release workflow starts with no permissions, grants only job-local privileges, and cannot publish before validation + CodeQL pass
- a production release is accepted only when GitHub reports it immutable; otherwise the workflow removes the mutable release/tag and fails closed
- parser, path, output, PR-CI, and release trust boundaries have a documented security review with permanent regression coverage for fixes

## v1.0 — Safety-gated stable release ✅

v1.0 is a stability and safety milestone, not a feature-count milestone. Detailed guarantees are in `docs/stability-v1.0.md`; concrete release evidence is mapped in `docs/v1.0-verification.md`.

Required before declaring stable:

- [x] Stable capability/policy schema with documented compatibility guarantees
- [x] Stable SARIF and machine-readable output contracts
- [x] Universal schema works across multiple real agent framework serialized formats
- [x] Semantic filesystem/network scope diff is production-style regression tested
- [x] Capability attack paths are evidence-based and conservatively worded
- [x] Safety benchmark is reproducible and published in the repository
- [x] No silent regression in the high-risk false-negative baseline
- [x] Input hardening/fuzz/security regression suites are green
- [x] CI, CodeQL, AgentCapDiff self-policy, and release-integrity checks are required green before merge
- [x] No known unresolved critical/high vulnerability in AgentCapDiff itself at release time
- [x] Threat model, limitations, supported versions, and security reporting process are current
- [x] Production install/action guidance uses trusted immutable release references

### v1.0 release gate

- capability schema version `1`, policy semantics, JSON scan output, SARIF 2.1.0 output, snapshots, and diffs have explicit 1.x compatibility guarantees and regression coverage
- framework conformance covers MCP, OpenAI API, OpenAI Agents SDK, Claude, LangChain/LangGraph-compatible, and CrewAI-style static serialized metadata without importing or executing target code
- filesystem/network scope regression coverage includes restricted, broad, unknown/dynamic, widening, edge, and no-false-expansion cases
- capability-path wording remains possible/evidence-backed and never claims runtime exploitability without evidence
- benchmark, fuzz/input-hardening, parser/path/output regressions, CI Python 3.11/3.12/3.13, CodeQL, self-policy, PR capability diff, project-state consistency, and release-integrity all pass on the final release PR head
- the repository issue tracker has no known unresolved critical/high AgentCapDiff vulnerability at final verification; this is not a claim that undiscovered vulnerabilities do not exist
- release metadata/docs agree on `1.0.0`, and production guidance uses reviewed full commit SHAs or verified immutable release tags

## What AgentCapDiff will not become

To protect users and keep the project differentiated, AgentCapDiff is **not** intended to become:

- an exploit framework
- a tool that runs unknown agents to see what happens
- a credential or secret collector
- a network vulnerability scanner
- a replacement for runtime sandboxing, authorization, code review, or secret isolation
- a system that promises an agent is safe because no finding was produced

The project should grow by making **capability change evidence more precise, portable, and reviewable** while keeping analysis static and low-risk.
