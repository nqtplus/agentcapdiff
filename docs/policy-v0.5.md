# v0.5 policy foundation

AgentCapDiff v0.5 is developing a more expressive least-privilege policy model while keeping evaluation static, deterministic, and conservative.

## Current development features

### Capability allowlists by tool

`allow_by_tool` constrains a named tool to an explicit set of normalized capability IDs. If a capability inferred for that tool is not present in its allowlist, AgentCapDiff emits a HIGH `capability.tool_allowlist_violation` finding.

```yaml
allow_by_tool:
  report_reader:
    - filesystem.read
  api_client:
    - network.external
```

This allowlist does not prove runtime enforcement. It only evaluates the normalized static capability evidence AgentCapDiff recognized.

### Scope constraints

`scope_constraints` can require allowed scope kinds and, optionally, exact statically observed scope values.

```yaml
scope_constraints:
  filesystem.write:
    allowed_kinds: [restricted]
    allowed_values:
      - ./reports/**
  network.external:
    allowed_kinds: [restricted]
    allowed_values:
      - api.example.com
```

Observed broad scope, a disallowed scope kind, or values outside the configured allowlist produce HIGH findings. Scope-value matching is deliberately exact in this development slice; it does not attempt dynamic glob, DNS, URL-reachability, or runtime authorization evaluation.

### Explicit unknown-scope handling

When a capability has a configured scope constraint but static analysis cannot establish the scope, `unknown_scope` controls policy behavior:

```yaml
unknown_scope: review  # deny | review | ignore
```

The safe default is `review`, which emits a MEDIUM `scope.unknown` finding. `deny` emits HIGH. `ignore` is available only as an explicit operator choice and must not be described as evidence that the unknown permission is safe.

### Deterministic precedence in this slice

Evaluation uses a conservative order for each capability/tool pair:

1. global `deny`
2. per-tool capability allowlist
3. scope constraint / unknown-scope policy
4. `require_review`
5. global risk-score threshold

A global deny therefore cannot be weakened by adding the same capability to a tool allowlist.

### CI default

The CLI and composite GitHub Action now default to `--fail-on medium`. This makes review-required and unknown-scope findings fail closed in unattended CI unless a repository explicitly chooses another threshold.

## Backwards compatibility

Legacy policies containing only `deny`, `require_review`, and `max_risk_score` remain valid and retain their previous evaluation semantics. New policy fields are additive.

## Still in progress for v0.5

The following roadmap work is intentionally not claimed complete yet:

- trust-boundary annotations
- policy inheritance with deterministic precedence across inherited files
- suppressions requiring reason and expiry
- policy-weakening diff warnings
- complete release-gate compatibility and review UX validation

Until those items and the v0.5 release gate are complete, package metadata remains `0.5.0.dev0` and the README must show v0.5 as IN_PROGRESS.

## Safety limits

Policy evaluation never executes or imports target repository code, probes discovered endpoints, resolves runtime authorization, or uses credentials. Unknown scope is uncertainty, not safety. A clean policy result is evidence about recognized static inputs, not proof that an agent is safe.
