# AgentCapDiff

[![CI](https://github.com/nqtplus/agentcapdiff/actions/workflows/ci.yml/badge.svg)](https://github.com/nqtplus/agentcapdiff/actions/workflows/ci.yml)
[![CodeQL](https://github.com/nqtplus/agentcapdiff/actions/workflows/codeql.yml/badge.svg)](https://github.com/nqtplus/agentcapdiff/actions/workflows/codeql.yml)

**Policy-as-code and capability diffing for AI agents.**

AgentCapDiff helps reviewers answer a deceptively hard question before an agent-enabled pull request is merged:

> **What can this agent do now that it could not do before?**

It inventories tool capabilities from OpenAI-style and MCP-like tool definitions, assigns transparent risk weights, evaluates a least-privilege policy, emits SARIF for GitHub code scanning, and compares capability snapshots across pull requests.

> Status: **early alpha**. The classifier is intentionally simple and explainable. Expect false positives while adapters and semantic scope rules mature.

## Why this exists

AI agents increasingly combine filesystem, shell, network, GitHub, email, database, and secret-bearing tools. Traditional code review shows *which lines changed*; it does not clearly show *which operational powers changed*.

AgentCapDiff treats agent capability as a reviewable artifact.

## Quick start

Install directly from the repository:

```bash
python -m pip install "git+https://github.com/nqtplus/agentcapdiff.git"
agentcapdiff scan ./agent --policy agentcapdiff.yaml
```

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

## Snapshots and diffs

```bash
agentcapdiff snapshot ./agent --output before.json
# make a change
agentcapdiff snapshot ./agent --output after.json
agentcapdiff diff before.json after.json
```

Machine-readable diff example:

```json
{
  "capabilities_added": ["shell.execute"],
  "capabilities_removed": [],
  "tools_added": ["shell_execute"],
  "tools_removed": [],
  "base_risk_score": 10,
  "head_risk_score": 45,
  "risk_delta": 35
}
```

For a reviewer-friendly summary:

```bash
agentcapdiff diff before.json after.json --format markdown
```

## PR-native capability diff

The included `PR capability diff` workflow checks out the pull request base commit into a detached Git worktree, scans base and head without executing target code, and writes a Markdown capability summary to the GitHub Actions step summary.

This makes capability expansion visible alongside normal test and security checks.

## GitHub Action

Until a stable major-version tag is published, pin the action to a commit for production use. For evaluation against the current default branch:

```yaml
- uses: nqtplus/agentcapdiff@main
  with:
    path: .
    policy: agentcapdiff.yaml
    fail-on: high
```

The repository also contains SARIF upload and CodeQL workflows.

## Supported inputs

- OpenAI-style JSON/YAML function tools
- MCP-like JSON/YAML tool objects with `name` + `inputSchema`
- Generic nested `tools` collections

Planned adapters and scope analysis are tracked in [ROADMAP.md](ROADMAP.md) and in GitHub Issues.

## Security model

AgentCapDiff is a **static policy aid**, not a sandbox, exploit scanner, runtime authorization system, or proof that an agent is safe. A clean scan must never be interpreted as permission to run untrusted tools with unrestricted credentials.

AgentCapDiff does not import target project code or execute discovered tools. See [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).

## Design principles

1. **Explainable over magical** — every inferred capability must have a visible reason.
2. **Diffs over dashboards** — PR reviewers need to see change, not just a score.
3. **Least privilege by default** — powerful capabilities should be explicitly reviewed.
4. **CI-native** — text, JSON, Markdown, SARIF, and stable exit behavior.
5. **Framework-neutral** — adapters normalize into one small capability model.

## Contributing

External bug reports, adapter examples, false-positive fixtures, and capability-taxonomy discussions are especially valuable. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
