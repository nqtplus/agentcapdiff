# Audit #25 — Policy YAML duplicate-key ambiguity

## Scope

This audit reviews raw YAML mapping semantics at the repository policy control plane, before inheritance, selector canonicalization, effective-policy evaluation, or sealed-result binding.

## Finding

PyYAML `safe_load()` safely avoids arbitrary Python object construction, but by default it accepts duplicate mapping keys and silently keeps the later value. For a security policy this creates parser ambiguity before AgentCapDiff's semantic validators can see the data.

Examples include:

```yaml
deny: [shell.execute]
deny: []
```

and nested controls such as:

```yaml
allow_by_tool:
  repo_tool: [github.write]
  repo_tool: []
```

The second definition silently replaced the first. A reviewer or another parser could therefore reason about a different effective control than the value AgentCapDiff evaluates. The same ambiguity existed inside inherited policy files.

Existing canonical selector collision checks do not solve this case because the first raw duplicate has already been discarded by the YAML loader before those checks run.

## Remediation

Policy parsing now uses a dedicated `UniqueKeySafeLoader`, derived from PyYAML `SafeLoader`, that rejects duplicate raw mapping keys at every mapping depth.

Duplicate detection occurs before PyYAML flattens YAML merge keys. This preserves the existing merge behavior where one `<<` merge plus an explicit local key intentionally overrides the inherited merged value, while two raw definitions of the same key in the same mapping are rejected.

The strict loader is local to the policy path. It does not monkeypatch PyYAML globally and does not silently alter discovery or snapshot parsing behavior.

Duplicate-key failures remain `yaml.YAMLError`/constructor failures and are normalized by the existing policy input boundary into a controlled `ValueError`. The CLI therefore returns its normal invalid-input exit code instead of evaluating a last-key-wins policy.

## Permanent regressions

Tests cover:

- duplicate root `deny` keys;
- quoted and unquoted forms of the same root key;
- duplicate nested tool selectors under `allow_by_tool`;
- duplicate keys in an inherited parent policy;
- valid YAML merge-key behavior with an explicit local override remaining compatible;
- CLI scanning with a duplicate policy key failing closed through exit code 3.

## Security effect

A policy author or untrusted repository can no longer shadow an earlier security control by repeating the same YAML key later in the same mapping. The raw policy representation must be unambiguous before inheritance and semantic policy validation begin.

## Compatibility

Policies with unique raw mapping keys are unchanged. Existing documented inheritance precedence remains unchanged. A single YAML merge key followed by an explicit local override remains valid.

Policies that relied on repeated raw YAML keys in one mapping are now rejected rather than interpreted by last-key-wins order. That behavior is intentional security hardening because duplicate security-control keys are ambiguous input, not a stable policy contract.

Capability rules, risk weights, scope semantics, policy precedence between distinct inherited files, public JSON/SARIF/snapshot structures, and package version remain unchanged at `1.0.0`.

## Follow-up boundary

Duplicate JSON keys in externally supplied snapshot artifacts and duplicate keys in general discovery metadata are separate parser surfaces. They are intentionally not changed in this audit so each trust boundary can be hardened with its own fail-closed compatibility analysis.
