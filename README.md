# AgentCapDiff

[![CI](https://github.com/nqtplus/agentcapdiff/actions/workflows/ci.yml/badge.svg)](https://github.com/nqtplus/agentcapdiff/actions/workflows/ci.yml)
[![CodeQL](https://github.com/nqtplus/agentcapdiff/actions/workflows/codeql.yml/badge.svg)](https://github.com/nqtplus/agentcapdiff/actions/workflows/codeql.yml)

**Policy-as-code and capability diffing for AI agents.**

AgentCapDiff helps reviewers answer a deceptively hard question before an agent-enabled pull request is merged:

> **What can this agent do now that it could not do before?**

It inventories tool capabilities from supported static JSON/YAML tool definitions, assigns transparent risk weights, evaluates a least-privilege policy, emits SARIF for GitHub code scanning, and compares capability snapshots across pull requests.

> Status: **v1.0 — IN_PROGRESS.** The stable release is gated on explicit compatibility/output contracts plus the existing benchmark, fuzz/security, CodeQL, self-policy, release-integrity, and immutable-release safeguards. Until every v1.0 gate is verified, the package/runtime version remains `1.0.0.dev0`. A clean result is evidence about recognized static inputs, **not proof that an agent is safe**.

## Why this exists

AI agents increasingly combine filesystem, shell, network, GitHub, email, database, and secret-bearing tools. Traditional code review shows *which lines changed*; it does not clearly show *which operational powers changed*.

AgentCapDiff treats agent capability as a reviewable artifact.

## v1.0 stability target

v1.0 freezes the 1.x compatibility expectations for the universal capability/policy semantics and machine-readable JSON/SARIF contracts without expanding AgentCapDiff into runtime execution. The detailed guarantees and release gates are documented in [docs/stability-v1.0.md](docs/stability-v1.0.md).

## Quick start

Install directly from the repository for evaluation:

```bash
python -m pip install "git+https://github.com/nqtplus/agentcapdiff.git"
agentcapdiff scan ./agent --policy agentcapdiff.yaml
```

For production CI, pin a reviewed full commit SHA or a verified immutable release tag instead of relying on a floating branch reference.

Or for local development:

```bash
python -m pip install -e ".[dev]"
ruff check .
pytest
```

Example scan output:

```text
AgentCapDiff
============
Tools inspected: 4
Capabilities: 4
Risk score: 85/100

Capability inventory:
  - filesystem.read: read_file
  - filesystem.write: create_file
  - network.external: fetch_url
  - shell.execute: shell_execute
```

## Capability policy

Legacy policy fields remain supported:

```yaml
max_risk_score: 60

deny:
  - secrets.access

require_review:
  - shell.execute
  - filesystem.write
  - email.send
  - github.write
```

v0.5 adds per-tool capability allowlists, static scope constraints, explicit unknown handling, trust-boundary review annotations, deterministic local inheritance, and temporary suppressions:

```yaml
extends:
  - policies/base.yml

allow_by_tool:
  report_reader:
    - filesystem.read
  api_client:
    - network.external

scope_constraints:
  filesystem.write:
    allowed_kinds: [restricted]
    allowed_values:
      - ./reports/**
  network.external:
    allowed_kinds: [restricted]
    allowed_values:
      - api.example.com

unknown_scope: review  # deny | review | ignore

trust_boundaries:
  api_client:
    boundary: internet
    trust: untrusted
    note: third-party service

suppressions:
  - rule_id: capability.review_required
    capability: filesystem.write
    tool: report_writer
    reason: reviewed migration window
    expires: 2026-09-01  # example only; use a short real expiry
```

Inheritance is deterministic: parents are applied in listed order, later parents override earlier parents, and the child policy overrides inherited values. Mapping fields merge by key. Inherited files must remain inside the root policy directory; cycles, excessive depth, escaping paths, malformed suppressions, and expired suppressions fail closed.

`unknown_scope: review` is the default. Unknown scope is not treated as safe. Suppressions require both a non-empty reason and an ISO expiry date, remain visible as informational evidence while active, and become invalid after expiry. The CLI and composite Action default to `--fail-on medium`, so review-required and unknown-scope findings fail unattended CI unless a repository explicitly chooses another threshold. See [docs/policy-v0.5.md](docs/policy-v0.5.md).

## Static filesystem and network scopes

v0.2 keeps existing capability IDs while attaching separate static scope evidence to filesystem and external-network capabilities. Scope is classified as `restricted`, `broad`, or `unknown`.

Examples of meaningful review changes include `./reports/**` → `/**` and `api.example.com` → arbitrary network access. Dynamic paths, traversal-like paths, unconstrained URL fields, and ambiguous metadata remain `unknown`; AgentCapDiff never upgrades uncertainty into a reassuring restriction.

Scope evidence is derived only from static tool metadata. AgentCapDiff does not execute tool code, resolve DNS, contact discovered endpoints, or prove that runtime enforcement matches the declared schema. See [docs/scopes.md](docs/scopes.md).

## Universal capability schema

v0.3 adds an explicit framework-neutral capability record with a versioned schema and first-class `scope`, `evidence`, and `confidence`. Supported static framework shapes retain adapter provenance as evidence while normalizing equivalent powers to the same capability IDs, risk semantics, policy decisions, and conservative scope semantics.

The adapter conformance suite checks equivalent filesystem/network privileges across MCP, OpenAI, OpenAI Agents SDK, Claude, LangChain, LangGraph-compatible, and CrewAI-style serialized metadata. It also verifies that dynamic scope remains `unknown` and that representing the same privilege through a different framework cannot silently weaken a deny-policy decision.

Snapshots remain backward-readable: the v0.2 capability ID list and fingerprint stay in place while v0.3 adds `capability_schema_version` and `capability_records`. Unsupported, runtime-generated, or ambiguous framework behavior remains unknown/generic rather than being treated as safe. See [docs/capability-schema.md](docs/capability-schema.md).

## Capability graph and possible paths

v0.4 adds a separately versioned capability graph derived only from already-recognized static capabilities. Deterministic rules identify combinations such as `secrets.access + network.external`, `filesystem.read + email.send`, and `github.write + shell.execute` as **possible** data-egress or supply-chain paths.

Severity and confidence are separate. Scope can raise path severity when evidence is broad or unresolved, while unknown scope lowers confidence rather than being treated as safe. Every path explanation states that static evidence does not prove runtime reachability or exploitability. The scanner never executes target code, probes endpoints, uses credentials, or attempts exploitation to validate a path.

Snapshots carry the graph as an additive field. Older snapshots without graph data remain readable, and PR Markdown highlights newly introduced possible paths without turning them into claims of confirmed exploitation. See [docs/capability-graph.md](docs/capability-graph.md).

## Snapshots and diffs

```bash
agentcapdiff snapshot ./agent --output before.json
# make a change
agentcapdiff snapshot ./agent --output after.json
agentcapdiff diff before.json after.json
```

New snapshots include a deterministic SHA-256 `capability_fingerprint` derived only from the sorted, unique capability IDs. Source paths, tool names, timestamps, findings, risk score, scope evidence, and capability-path data do not affect the legacy fingerprint. See [docs/snapshots.md](docs/snapshots.md) for the canonicalization contract.

Snapshots also retain filesystem/network scope evidence and the normalized effective policy. v0.5 computes a separate policy fingerprint for diffing; it does not change the legacy capability fingerprint. Older snapshots without policy metadata remain readable and do not generate fabricated weakening warnings.

Machine-readable diff example:

```json
{
  "capabilities_added": ["shell.execute"],
  "capabilities_removed": [],
  "tools_added": ["shell_execute"],
  "tools_removed": [],
  "scope_changes": [],
  "scope_expansions": [],
  "paths_added": [],
  "policy_changed": true,
  "policy_weakening_warnings": [],
  "base_risk_score": 10,
  "head_risk_score": 45,
  "risk_delta": 35,
  "fingerprint_changed": true
}
```

For a reviewer-friendly summary:

```bash
agentcapdiff diff before.json after.json --format markdown
```

## PR-native capability diff

The included `PR capability diff` workflow checks out the pull request base commit into a detached Git worktree, scans base and head without executing target code, and writes a Markdown capability summary to the GitHub Actions step summary.

This makes capability expansion, statically proven scope expansion, newly introduced possible capability paths, trust-boundary context, active temporary suppressions, and policy weakening visible alongside normal test and security checks. Weakening warnings include removed denies/review requirements, raised risk thresholds, relaxed unknown handling, expanded allowlists/scope constraints, new or extended suppressions, and removed trust-boundary annotations.

## Safety benchmark

v0.9 includes a committed positive/negative/ambiguous fixture corpus and a machine-readable benchmark summary. CI gates high-risk false negatives and parser failures against `benchmarks/baseline.json`, while nuisance false positives and unknown scope are reported separately rather than hidden in one score.

Run it locally with:

```bash
python -m agentcapdiff.benchmark --output benchmark-summary.json
```

Every fixed classification or security regression must add a permanent sanitized fixture. The benchmark remains static and does not execute target code, probe endpoints, or use credentials. See [docs/safety-benchmark.md](docs/safety-benchmark.md).

## Release integrity

v0.9 treats the release pipeline as a security boundary. All external Actions in repository workflows are pinned to full commit SHAs, direct CI/release dependencies are reviewed exact pins, and Dependabot opens reviewable update PRs for both Python and GitHub Actions.

A tag-triggered release must match the finalized package/runtime version and pass release-integrity checks, the test suite, Ruff, the safety benchmark, AgentCapDiff self-policy, and CodeQL before publication. The publish job builds the wheel/source distribution, creates `SHA256SUMS`, generates an SPDX 2.3 SBOM, and records GitHub build-provenance and SBOM attestations.

Repository release immutability must be enabled in GitHub before a production tag is published. The workflow publishes from a draft, then accepts the release only if GitHub reports `isImmutable=true`; otherwise it fails closed and attempts to remove the mutable release/tag.

See [docs/release-integrity.md](docs/release-integrity.md), [RELEASE.md](RELEASE.md), and [docs/security-review-v0.9.md](docs/security-review-v0.9.md).

## GitHub Action

For production use, pin the Action to a reviewed full commit SHA. A verified immutable release tag is also suitable when its release and attestations have been reviewed. Floating branches are for evaluation/development only:

```yaml
- uses: nqtplus/agentcapdiff@<reviewed-full-commit-sha>
  with:
    path: .
    policy: agentcapdiff.yaml
    fail-on: medium
```

The repository also contains SARIF upload, CodeQL, PR capability-diff, project-state consistency, release-integrity, and least-privilege release workflows.

## Supported static inputs

- OpenAI API-style JSON/YAML function tools (`function.parameters` or direct `parameters`)
- OpenAI Agents SDK-style serialized function tools (`params_json_schema`)
- MCP JSON/YAML tool objects (`name` + `inputSchema`)
- Claude client-tool JSON/YAML objects (`name` + `input_schema`)
- LangChain/LangGraph-compatible serialized tool metadata (`args_schema` / `tool_call_schema` with static provenance signals)
- CrewAI-style serialized tool metadata (`args_schema` with CrewAI provenance signals)
- Generic nested `tools` collections, retained at lower confidence when framework attribution is ambiguous

Framework support means recognition of **static serialized metadata only**. AgentCapDiff does not import Python/JavaScript SDKs, instantiate decorators/classes, traverse live object graphs, or execute target code to materialize a schema. Runtime-only or unsupported shapes therefore remain outside positive adapter attribution rather than being silently labeled safe.

Discovery treats scanned files as untrusted input. It uses safe YAML loading, rejects symlinked scan inputs/roots, checks resolved candidates stay inside the scan-root boundary, and bounds per-file bytes, total parsed bytes, candidate document count, nesting depth, and structured-node traversal. Inputs that exceed safety limits fail closed rather than producing a misleading clean scan.

The hardening suite includes malformed/pathological input cases, deterministic fuzz/property tests, path traversal/symlink regression coverage, output-injection regression tests, and checks that discovered endpoints do not trigger network access.

Roadmap and future capability work are tracked in [ROADMAP.md](ROADMAP.md) and in GitHub Issues.

## Security model

AgentCapDiff is a **static policy aid**, not a sandbox, exploit scanner, runtime authorization system, or proof that an agent is safe. A clean scan must never be interpreted as permission to run untrusted tools with unrestricted credentials.

AgentCapDiff does not import target project code, execute discovered tools, probe discovered endpoints, or collect credentials. When effective permission scope cannot be established statically, the safe interpretation is **unknown**, not safe or restricted.

Use AgentCapDiff as one layer of defense in depth alongside ordinary code review, runtime least-privilege authorization, sandboxing/isolation where appropriate, secret isolation, dependency controls, and network/runtime policy enforcement.
