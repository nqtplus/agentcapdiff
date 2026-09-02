# AgentCapDiff

[![CI](https://github.com/nqtplus/agentcapdiff/actions/workflows/ci.yml/badge.svg)](https://github.com/nqtplus/agentcapdiff/actions/workflows/ci.yml)
[![CodeQL](https://github.com/nqtplus/agentcapdiff/actions/workflows/codeql.yml/badge.svg)](https://github.com/nqtplus/agentcapdiff/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/nqtplus/agentcapdiff)](https://github.com/nqtplus/agentcapdiff/releases/latest)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**AI agent security policy-as-code for reviewing capability and permission changes before they reach production.**

AgentCapDiff statically inventories AI-agent tools, maps them to normalized capabilities, evaluates least-privilege policy, emits SARIF for GitHub code scanning, and diffs capability snapshots across pull requests.

It is designed for **MCP**, **OpenAI / OpenAI Agents SDK**, **Claude**, **LangChain**, **LangGraph**, **CrewAI**, and generic JSON/YAML tool definitions.

> **Core review question:** What can this agent do now that it could not do before?

AgentCapDiff helps make changes such as new shell execution, broader filesystem access, external-network access, secret access, GitHub writes, or policy weakening visible during code review.

**Current stable release: v1.0.1.** AgentCapDiff is a static policy aid, not a runtime sandbox or proof that an agent is safe.

## Why AgentCapDiff

Traditional code review shows which lines changed. AI-agent review also needs to show which **operational powers** changed.

AgentCapDiff turns tool access and agent capability into reviewable security artifacts:

| Need | AgentCapDiff |
| --- | --- |
| AI agent capability inventory | Normalizes recognized static tool definitions into capability IDs |
| Least-privilege enforcement | Policy-as-code with deny, review, allowlist, scope, and suppression rules |
| PR security review | Compares capability snapshots and highlights newly introduced powers |
| MCP / agent-tool security | Recognizes multiple common serialized tool-schema formats |
| Scope review | Classifies filesystem and network scope as restricted, broad, or unknown |
| Risky capability combinations | Identifies possible static capability paths such as secrets + external network |
| GitHub security integration | Emits SARIF and includes PR-native capability-diff workflows |
| CI enforcement | Fails on configurable medium/high findings without executing target code |

## Quick start

Install directly from the repository for evaluation:

```bash
python -m pip install "git+https://github.com/nqtplus/agentcapdiff.git"
agentcapdiff scan ./agent --policy agentcapdiff.yaml
```

Example output:

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

For local development:

```bash
python -m pip install -e ".[dev]"
ruff check .
pytest
```

For production CI, pin a reviewed full commit SHA or a verified immutable release tag rather than a floating branch.

## GitHub Action

AgentCapDiff can run directly in GitHub Actions:

```yaml
- uses: nqtplus/agentcapdiff@<reviewed-full-commit-sha>
  with:
    path: .
    policy: agentcapdiff.yaml
    fail-on: medium
```

The repository includes CI, CodeQL, SARIF upload, PR capability diff, safety benchmark, self-policy, release-integrity, and immutable-release gates.

## What AgentCapDiff detects

AgentCapDiff focuses on security-relevant AI-agent and tool permissions, including recognized forms of:

- `filesystem.read`
- `filesystem.write`
- `network.external`
- `shell.execute`
- `secrets.access`
- `email.send`
- `github.write`

It also tracks static scope evidence and possible capability combinations. For example, `secrets.access + network.external` may indicate a possible data-egress path that deserves review.

Severity and confidence are kept separate. Unknown or dynamic scope is not silently treated as safe.

## Supported static inputs

AgentCapDiff recognizes static serialized metadata for:

- OpenAI API-style JSON/YAML function tools (`function.parameters` or direct `parameters`)
- OpenAI Agents SDK-style serialized function tools (`params_json_schema`)
- MCP JSON/YAML tool objects (`name` + `inputSchema`)
- Claude client-tool JSON/YAML objects (`name` + `input_schema`)
- LangChain / LangGraph-compatible serialized tool metadata (`args_schema` / `tool_call_schema`)
- CrewAI-style serialized tool metadata (`args_schema` with CrewAI provenance signals)
- Generic nested `tools` collections when framework attribution is ambiguous

Framework support means **static serialized metadata recognition only**. AgentCapDiff does not import SDKs, instantiate tool classes, execute target code, contact discovered endpoints, or use credentials to materialize runtime behavior.

## Capability policy

A minimal policy can define risk thresholds and capabilities that require review:

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

More advanced policy supports per-tool allowlists, static scope constraints, explicit unknown handling, trust-boundary annotations, deterministic local inheritance, and temporary suppressions:

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

unknown_scope: review

trust_boundaries:
  api_client:
    boundary: internet
    trust: untrusted
    note: third-party service
```

See [docs/policy-v0.5.md](docs/policy-v0.5.md) for policy semantics.

## Capability snapshots and diffs

Create before/after snapshots and compare the agent's effective capabilities:

```bash
agentcapdiff snapshot ./agent --output before.json
# make a change
agentcapdiff snapshot ./agent --output after.json
agentcapdiff diff before.json after.json
```

For a reviewer-friendly summary:

```bash
agentcapdiff diff before.json after.json --format markdown
```

Diff output can show capabilities and tools added or removed, scope expansion, possible capability paths, policy changes, risk deltas, and fingerprint changes.

See [docs/snapshots.md](docs/snapshots.md) and [docs/capability-graph.md](docs/capability-graph.md).

## PR-native capability review

The included **PR capability diff** workflow checks out the pull-request base commit into a detached Git worktree, scans base and head without executing target code, and writes a Markdown capability summary to the GitHub Actions step summary.

This makes capability expansion, static scope expansion, possible capability paths, trust-boundary context, active suppressions, and policy weakening visible alongside ordinary test and security checks.

## Security model

AgentCapDiff is a **static policy aid**. It is not:

- a sandbox;
- an exploit scanner;
- a runtime authorization system;
- proof that an AI agent is safe.

A clean scan means that recognized static inputs satisfied the configured checks. It must not be interpreted as permission to run untrusted tools with unrestricted credentials.

Use AgentCapDiff as one layer of defense in depth alongside code review, runtime least-privilege authorization, sandboxing or isolation where appropriate, secret isolation, dependency controls, and network/runtime policy enforcement.

Discovery treats scanned files as untrusted input. It uses safe YAML loading, rejects symlinked scan inputs/roots, enforces scan-root boundaries, bounds parsing work, and fails closed on inputs that exceed safety limits.

## Verification and release integrity

The v1.x stability contract covers capability/policy semantics and machine-readable JSON/SARIF compatibility. Release gates include multi-framework conformance, semantic scope tests, capability-path tests, benchmark fixtures, fuzz/security testing, CodeQL, self-policy checks, and release-integrity validation.

Release artifacts include wheel/source distributions, SHA-256 checksums, an SPDX SBOM, and GitHub build provenance / SBOM attestations. Production releases are required to pass immutable-release enforcement.

- [v1.0 stability contract](docs/stability-v1.0.md)
- [v1.0 verification map](docs/v1.0-verification.md)
- [Safety benchmark](docs/safety-benchmark.md)
- [Release integrity](docs/release-integrity.md)
- [Security review](docs/security-review-v0.9.md)

## Documentation

- [Capability schema](docs/capability-schema.md)
- [Static scopes](docs/scopes.md)
- [Capability graph](docs/capability-graph.md)
- [Policy model](docs/policy-v0.5.md)
- [Snapshots and fingerprints](docs/snapshots.md)
- [Safety benchmark](docs/safety-benchmark.md)
- [Release process](RELEASE.md)
- [Roadmap](ROADMAP.md)

## Project scope

AgentCapDiff is intentionally focused on **static AI-agent capability analysis, policy-as-code, least privilege, and pull-request review**. Runtime-only or unsupported behavior remains unknown rather than being labeled safe.
