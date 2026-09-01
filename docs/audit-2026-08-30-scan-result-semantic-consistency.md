# ScanResult semantic consistency audit — 2026-08-30

## Scope

This is one coherent post-v1.0 audit pass covering the internal semantic consistency of scanner-produced `ScanResult` values before they are serialized or used for CLI decisions.

Baseline main before this audit:

`cf290a2c2bcde400ccf276fbd6e032de58babd74`

The product remains v1.0.0. This pass does not change capability IDs, risk weights, policy precedence, graph schema, snapshot schema, JSON/SARIF top-level contracts, runtime execution boundaries, or the meaning of a clean scan.

## Finding — scanner construction was correct but not sealed against internal drift

`scan()` discovers tools, infers capabilities, builds the graph, materializes the effective policy, and evaluates findings in one deterministic flow. However, `ScanResult` is intentionally a mutable Python object. Before this audit there was no final construction invariant or semantic fingerprint tying these fields together.

A future refactor, plugin/library caller, or accidental mutation could therefore make one field stale while another changed, for example:

- capabilities no longer matching discovered tools;
- capability graph no longer matching capabilities;
- policy record no longer matching the policy used to evaluate findings;
- findings no longer matching capabilities/policy/risk;
- risk/max-severity, graph, or findings being changed after scanner construction before output.

Snapshot artifact validation already rejects contradictory *loaded* snapshots, but that protection happens after a snapshot exists. Scanner-produced output should not be able to create the contradiction in the first place.

## Continuation finding — library serializers could bypass the seal check

The first remediation draft re-checked sealed results at CLI scan/snapshot boundaries and through `ScanResult.to_dict()`. A continuation review found that direct library callers could still pass a mutated sealed result to `text_report()`, `sarif_report()`, or `snapshot_payload()` / `write_snapshot()` and serialize stale or contradictory state without invoking the CLI guard.

That was a real semantic-boundary gap even though normal CLI use was already protected. The remediation was extended so every built-in `ScanResult` output serializer checks the seal itself. Because `assert_consistent()` is intentionally a no-op for manually constructed unsealed results, existing 1.x library compatibility is preserved.

## Remediation

Scanner-produced results now receive an internal semantic seal after policy evaluation.

The seal validates that:

1. every inferred capability references a discovered tool;
2. the capability graph exactly recomputes from the current capabilities;
3. the in-memory snapshot-style projection passes the same cross-field semantic reconciliation used for untrusted snapshots;
4. the effective policy record matches the runtime `Policy` used by the scanner;
5. policy findings exactly recompute from the capabilities, effective policy, and risk score.

After validation, a private SHA-256 semantic fingerprint is stored over the scanner result's security-relevant output state. The fingerprint is an internal runtime guard only; it is not added to JSON, SARIF, snapshot, or other stable 1.x machine-readable output.

Before built-in output serialization, the sealed result is checked again. This includes CLI scan/snapshot output, JSON serialization through `ScanResult.to_dict()`, text reports, SARIF reports, and snapshot payload/writes. If graph, policy, findings, tools, capabilities, risk, or max severity drift after sealing, output fails closed rather than emitting a trustworthy-looking inconsistent result.

## Compatibility boundary

The seal applies automatically to results returned by `scan()`.

Manually constructed `ScanResult` values remain unsealed by default and retain their existing 1.x library behavior. This is intentional: tests and library consumers may construct partial result objects for formatting or diff fixtures without representing a complete scanner run. The audit does not silently redefine those objects as invalid.

The private seal field is excluded from equality, repr, constructors, and serialized output. Existing stable public keys remain unchanged.

## Regression coverage

Permanent tests cover:

- a real `scan()` result is sealed and passes semantic verification;
- sealing rejects findings that do not match the effective policy;
- sealing rejects capabilities whose tool is absent from discovery;
- graph mutation after sealing is rejected before JSON serialization;
- policy mutation after sealing is rejected;
- finding mutation after sealing is rejected;
- text, SARIF, and snapshot library serializers reject a mutated sealed result;
- manually constructed unsealed `ScanResult` values keep existing 1.x JSON, text, SARIF, and snapshot serialization behavior.

## Residual boundary

This is an internal consistency guarantee, not an immutability or runtime-security guarantee. Python callers can deliberately construct unsealed results, and the scanner still relies on the correctness of its static discovery/classification/policy logic. The seal prevents contradictory scanner-produced evidence from being silently emitted; it does not prove the analyzed agent is safe.

No target repository code is imported or executed, no discovered endpoint is contacted, and no credentials are requested or used by this audit.
