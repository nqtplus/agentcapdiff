# v0.5 policy maturity and safe review UX

AgentCapDiff v0.5 provides a more expressive least-privilege policy model while keeping evaluation static, deterministic, conservative, and backwards compatible with legacy policy files.

## Capability allowlists by tool

`allow_by_tool` constrains a named tool to an explicit set of normalized capability IDs. If a capability inferred for that tool is not present in its allowlist, AgentCapDiff emits a HIGH `capability.tool_allowlist_violation` finding.

```yaml
allow_by_tool:
  report_reader:
    - filesystem.read
  api_client:
    - network.external
```

This allowlist does not prove runtime enforcement. It only evaluates the normalized static capability evidence AgentCapDiff recognized.

## Scope constraints

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

Observed broad scope, a disallowed scope kind, or values outside the configured allowlist produce HIGH findings. Scope-value matching is deliberately exact; it does not attempt dynamic glob, DNS, URL-reachability, or runtime authorization evaluation.

## Explicit unknown-scope handling

When a capability has a configured scope constraint but static analysis cannot establish the scope, `unknown_scope` controls policy behavior:

```yaml
unknown_scope: review  # deny | review | ignore
```

The safe default is `review`, which emits a MEDIUM `scope.unknown` finding. `deny` emits HIGH. `ignore` is available only as an explicit operator choice and must not be described as evidence that the unknown permission is safe.

## Trust-boundary annotations

Teams can attach review context to named tools without pretending that static metadata proves runtime isolation:

```yaml
trust_boundaries:
  api_client:
    boundary: internet
    trust: untrusted
    note: third-party service
```

`boundary` is a non-empty review label. `trust` is one of `trusted`, `untrusted`, or `unknown`; `unknown` is the default when the short string form is used. Trust-boundary annotations are included in effective policy records and review output. They do **not** authorize, sandbox, or establish a runtime security boundary.

## Deterministic policy inheritance

A policy can inherit other local policy files:

```yaml
extends:
  - policies/company-base.yml
  - policies/team-base.yml

max_risk_score: 50
```

Precedence is deterministic:

1. parent policies are loaded in listed order;
2. later parents override earlier parents;
3. the child policy overrides inherited values;
4. `allow_by_tool`, `scope_constraints`, and `trust_boundaries` merge by mapping key, with the later definition for the same key winning;
5. list/scalar fields such as `deny`, `require_review`, `suppressions`, `unknown_scope`, and `max_risk_score` are replaced when explicitly defined by a later policy.

Inheritance is intentionally local. Absolute paths are rejected, every inherited file must resolve inside the root policy directory, symlinked policy files are rejected, cycles are rejected, and inheritance depth is bounded. These controls reduce the chance that scanning an untrusted repository causes policy loading to read unrelated local files.

Because child precedence can intentionally relax a parent policy, PR policy diffing separately warns when the effective policy becomes less restrictive.

## Temporary suppressions: reason + expiry required

Suppressions are explicit, temporary exceptions to findings:

```yaml
suppressions:
  - rule_id: capability.review_required
    capability: filesystem.write
    tool: report_writer
    reason: reviewed migration window
    expires: 2026-09-01
```

`rule_id`, a non-empty `reason`, and an ISO `YYYY-MM-DD` `expires` date are mandatory. `capability` and `tool` narrow the selector and are optional. An active matching suppression replaces the original finding with an INFO `policy.suppressed` record that retains the reason and expiry so the exception remains visible in reports.

Expiry is evaluated by UTC date. A suppression is valid through its expiry date; after that date the policy is invalid and scanning fails closed. Malformed suppression entries also invalidate the policy. This prevents an old exception from silently becoming permanent.

## Evaluation precedence

For each capability/tool pair, enforcement remains conservative and deterministic:

1. global `deny`
2. per-tool capability allowlist
3. scope constraint / unknown-scope policy
4. `require_review`
5. global risk-score threshold
6. a valid, unexpired matching suppression may convert the resulting finding to visible INFO suppression evidence

A global deny therefore cannot be weakened merely by adding the same capability to a tool allowlist. Suppressions are the explicit temporary exception mechanism and must carry reason + expiry.

## Policy fingerprints and weakening warnings

Snapshots now carry the normalized effective policy as an additive field and compute a separate policy fingerprint during diffing. The legacy capability fingerprint contract is unchanged.

When both base and head snapshots contain effective policy metadata, PR diff output warns about changes that reduce policy strictness or review visibility, including:

- global denies removed;
- human-review requirements removed;
- `max_risk_score` raised;
- `unknown_scope` relaxed from `deny` to `review`/`ignore` or from `review` to `ignore`;
- per-tool allowlists removed or expanded;
- scope constraints removed or expanded;
- temporary suppressions added or extended;
- trust-boundary annotations removed.

Policy weakening can therefore be visible even when the normalized capability inventory is unchanged. Old snapshots without policy metadata remain readable and do not receive fabricated weakening warnings because no trustworthy policy baseline exists in those snapshots.

## CI default

The CLI and composite GitHub Action default to `--fail-on medium`. This makes review-required and unknown-scope findings fail closed in unattended CI unless a repository explicitly chooses another threshold.

## Backwards compatibility

Legacy policies containing only `deny`, `require_review`, and `max_risk_score` remain valid and retain their previous evaluation semantics. All v0.5 fields are additive. Snapshot policy metadata is additive, and snapshots written before v0.5 remain readable.

## Safety limits

Policy evaluation never executes or imports target repository code, probes discovered endpoints, resolves runtime authorization, or uses credentials. Inheritance only reads explicitly referenced local YAML policy files inside the root policy directory. Unknown scope is uncertainty, not safety. Trust annotations are review context, not enforcement. A clean policy result is evidence about recognized static inputs, not proof that an agent is safe.
