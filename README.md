# AgentCapDiff

**Policy-as-code and capability diffing for AI agents.**

AgentCapDiff helps reviewers answer a deceptively hard question before an agent-enabled pull request is merged:

> **What can this agent do now that it could not do before?**

It inventories tool capabilities from OpenAI-style and MCP-like tool definitions, assigns transparent risk weights, evaluates a least-privilege policy, emits SARIF for GitHub code scanning, and produces snapshots that can be diffed in CI.

> Status: **early alpha (v0.1.0)**. The classifier is intentionally simple and explainable. Expect false positives while adapters and semantic rules mature.

## Why this exists

AI agents increasingly combine filesystem, shell, network, GitHub, email, database, and secret-bearing tools. Traditional code review shows *which lines changed*; it does not clearly show *which operational powers changed*.

AgentCapDiff treats agent capability as a reviewable artifact.

## Quick start

```bash
python -m pip install -e .
agentcapdiff scan examples --policy agentcapdiff.yaml
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

## Capability snapshots and diffs

```bash
agentcapdiff snapshot ./agent --output before.json
# make a change
agentcapdiff snapshot ./agent --output after.json
agentcapdiff diff before.json after.json
```

Example:

```json
{
  "capabilities_added": ["shell.execute"],
  "capabilities_removed": [],
  "tools_added": ["shell_execute"],
  "tools_removed": [],
  "risk_delta": 35
}
```

## GitHub Action

Once this repository is published, a project can use:

```yaml
- uses: nqtplus/agentcapdiff@v1
  with:
    path: .
    policy: agentcapdiff.yaml
    fail-on: high
```

The repository also contains a SARIF workflow so findings can appear in GitHub code scanning.

## Supported inputs in v0.1

- OpenAI-style JSON/YAML function tools
- MCP-like JSON/YAML tool objects with `name` + `inputSchema`
- Generic nested `tools` collections

Planned adapters are tracked in [ROADMAP.md](ROADMAP.md).

## Security model

AgentCapDiff is a **static policy aid**, not a sandbox, exploit scanner, or proof that an agent is safe. A clean scan must never be interpreted as permission to run untrusted tools with unrestricted credentials.

See [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).

## Design principles

1. **Explainable over magical** — every inferred capability must have a visible reason.
2. **Diffs over dashboards** — PR reviewers need to see change, not just a score.
3. **Least privilege by default** — powerful capabilities should be explicitly reviewed.
4. **CI-native** — text, JSON, SARIF, stable exit codes.
5. **Framework-neutral** — adapters should normalize into one small capability model.

## Contributing

External bug reports, adapter examples, false-positive fixtures, and capability-taxonomy discussions are especially valuable. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
