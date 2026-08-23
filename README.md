# AgentCapDiff

[![CI](https://github.com/nqtplus/agentcapdiff/actions/workflows/ci.yml/badge.svg)](https://github.com/nqtplus/agentcapdiff/actions/workflows/ci.yml)
[![CodeQL](https://github.com/nqtplus/agentcapdiff/actions/workflows/codeql.yml/badge.svg)](https://github.com/nqtplus/agentcapdiff/actions/workflows/codeql.yml)

**Policy-as-code and capability diffing for AI agents.**

AgentCapDiff helps reviewers answer a deceptively hard question before an agent-enabled pull request is merged:

> **What can this agent do now that it could not do before?**

It inventories tool capabilities from supported static JSON/YAML tool definitions, assigns transparent risk weights, evaluates a least-privilege policy, emits SARIF for GitHub code scanning, and compares capability snapshots across pull requests.

> Status: **v0.3.0 alpha — universal capability schema + adapter conformance complete.** Static adapter support covers MCP, OpenAI/OpenAI Agents SDK, Claude, LangChain/LangGraph-compatible metadata, and CrewAI-style metadata. The classifier remains intentionally explainable and conservative. Expect false positives and false negatives while schema coverage matures. A clean result is evidence about recognized static inputs, **not proof that an agent is safe**.

## Why this exists

AI agents increasingly combine filesystem, shell, network, GitHub, email, database, and secret-bearing tools. Traditional code review shows *which lines changed*; it does not clearly show *which operational powers changed*.

AgentCapDiff treats agent capability as a reviewable artifact.

## Quick start

Install directly from the repository for evaluation:

```bash
python -m pip install "git+https://github.com/nqtplus/agentcapdiff.git"
agentcapdiff scan ./agent --policy agentcapdiff.yaml
```

For production CI, pin a reviewed immutable commit SHA or trusted release tag instead of relying on a floating branch reference.

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

## Static filesystem and network scopes

v0.2 keeps existing capability IDs while attaching separate static scope evidence to filesystem and external-network capabilities. Scope is classified as `restricted`, `broad`, or `unknown`.

Examples of meaningful review changes include `./reports/**` → `/**` and `api.example.com` → arbitrary network access. Dynamic paths, traversal-like paths, unconstrained URL fields, and ambiguous metadata remain `unknown`; AgentCapDiff never upgrades uncertainty into a reassuring restriction.

Scope evidence is derived only from static tool metadata. AgentCapDiff does not execute tool code, resolve DNS, contact discovered endpoints, or prove that runtime enforcement matches the declared schema. See [docs/scopes.md](docs/scopes.md).

## Universal capability schema

v0.3 adds an explicit framework-neutral capability record with a versioned schema and first-class `scope`, `evidence`, and `confidence`. Supported static framework shapes retain adapter provenance as evidence while normalizing equivalent powers to the same capability IDs, risk semantics, policy decisions, and conservative scope semantics.

The adapter conformance suite checks equivalent filesystem/network privileges across MCP, OpenAI, OpenAI Agents SDK, Claude, LangChain, LangGraph-compatible, and CrewAI-style serialized metadata. It also verifies that dynamic scope remains `unknown` and that representing the same privilege through a different framework cannot silently weaken a deny-policy decision.

Snapshots remain backward-readable: the v0.2 capability ID list and fingerprint stay in place while v0.3 adds `capability_schema_version` and `capability_records`. Unsupported, runtime-generated, or ambiguous framework behavior remains unknown/generic rather than being treated as safe. See [docs/capability-schema.md](docs/capability-schema.md).

## Snapshots and diffs

```bash
agentcapdiff snapshot ./agent --output before.json
# make a change
agentcapdiff snapshot ./agent --output after.json
agentcapdiff diff before.json after.json
```

New snapshots include a deterministic SHA-256 `capability_fingerprint` derived only from the sorted, unique capability IDs. Source paths, tool names, timestamps, findings, risk score, and scope evidence do not affect the fingerprint. See [docs/snapshots.md](docs/snapshots.md) for the canonicalization contract.

Snapshots also retain filesystem/network scope evidence separately so semantic scope changes can be reviewed without changing capability IDs or fingerprint compatibility.

Machine-readable diff example:

```json
{
  "capabilities_added": ["shell.execute"],
  "capabilities_removed": [],
  "tools_added": ["shell_execute"],
  "tools_removed": [],
  "scope_changes": [],
  "scope_expansions": [],
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

This makes capability expansion and statically proven scope expansion visible alongside normal test and security checks.

## GitHub Action

Until a stable major-version tag is published, pin the action to a reviewed immutable commit for production use. A floating branch is suitable only for evaluation or development:

```yaml
- uses: nqtplus/agentcapdiff@<reviewed-commit-sha>
  with:
    path: .
    policy: agentcapdiff.yaml
    fail-on: high
```

The repository also contains SARIF upload, CodeQL, PR capability-diff, and project-state consistency workflows.

## Supported static inputs

- OpenAI API-style JSON/YAML function tools (`function.parameters` or direct `parameters`)
- OpenAI Agents SDK-style serialized function tools (`params_json_schema`)
- MCP JSON/YAML tool objects (`name` + `inputSchema`)
- Claude client-tool JSON/YAML objects (`name` + `input_schema`)
- LangChain/LangGraph-compatible serialized tool metadata (`args_schema` / `tool_call_schema` with static provenance signals)
- CrewAI-style serialized tool metadata (`args_schema` with CrewAI provenance signals)
- Generic nested `tools` collections, retained at lower confidence when framework attribution is ambiguous

Framework support means recognition of **static serialized metadata only**. AgentCapDiff does not import Python/JavaScript SDKs, instantiate decorators/classes, traverse live object graphs, or execute target code to materialize a schema. Runtime-only or unsupported shapes therefore remain outside positive adapter attribution rather than being silently labeled safe.

Discovery treats scanned files as untrusted input. It uses safe YAML loading, rejects symlinked scan inputs, and bounds per-file bytes, total parsed bytes, candidate document count, nesting depth, and structured-node traversal. Inputs that exceed safety limits fail closed rather than producing a misleading clean scan.

The v0.2 hardening suite includes malformed/pathological input cases, deterministic fuzz/property tests, path traversal/symlink regression coverage, output-injection regression tests, and checks that discovered endpoints do not trigger network access.

Roadmap and future capability work are tracked in [ROADMAP.md](ROADMAP.md) and in GitHub Issues.

## Security model

AgentCapDiff is a **static policy aid**, not a sandbox, exploit scanner, runtime authorization system, or proof that an agent is safe. A clean scan must never be interpreted as permission to run untrusted tools with unrestricted credentials.

AgentCapDiff does not import target project code, execute discovered tools, probe discovered endpoints, or collect credentials. When effective permission scope cannot be established statically, the safe interpretation is **unknown**, not safe or restricted.

Use AgentCapDiff as one layer of defense in depth alongside ordinary code review, runtime least-privilege authorization, sandboxing/isolation where appropriate, secret isolation, dependency controls, and network/runtime policy enforcement.
