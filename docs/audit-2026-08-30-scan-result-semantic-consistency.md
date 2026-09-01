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

## Continuation finding — idempotent reseal was not bound to the supplied policy

A further continuation review found that calling `seal()` on an already sealed result verified the stored fingerprint and returned before comparing the supplied `Policy` with the result's recorded effective policy. The result itself did not become inconsistent, but a caller could successfully invoke `result.seal(policy_b)` on a result originally sealed under `policy_a`, creating a misleading API success at exactly the trust boundary this audit is intended to make explicit.

Resealing is now idempotent only when the supplied effective policy serializes to the same policy record already bound into the result. A different policy fails closed before the existing seal is accepted.

## Continuation finding — verified mapping outputs exposed live aliases

A final output-boundary review found that `ScanResult.to_dict()` and `snapshot_payload()` returned the exact mutable `policy` and `capability_graph` dictionaries stored inside the result. A caller could therefore receive an output after semantic verification, mutate a nested mapping, and simultaneously mutate the sealed result through the shared object reference. The next guarded serialization would fail closed, but the already-returned output could be changed after its verification point and the internal state would be altered as a side effect.

For scanner-sealed results, mapping outputs are now detached before they cross the library boundary. `snapshot_payload()` reuses the detached mapping projection from `to_dict()`. Manually constructed unsealed 1.x objects retain their historical alias behavior so the audit does not silently change existing fixture/library semantics outside the scanner-sealed path.

## Remediation

Scanner-produced results now receive an internal semantic seal after policy evaluation.

The seal validates that:

1. every inferred capability references a discovered tool;
2. the capability graph exactly recomputes from the current capabilities;
3. the in-memory snapshot-style projection passes the same cross-field semantic reconciliation used for untrusted snapshots;
4. the effective policy record matches the runtime `Policy` used by the scanner, including idempotent reseal attempts;
5. policy findings exactly recompute from the capabilities, effective policy, and risk score.

After validation, a private SHA-256 semantic fingerprint is stored over the scanner result's security-relevant output state. The fingerprint is an internal runtime guard only; it is not added to JSON, SARIF, snapshot, or other stable 1.x machine-readable output.

Before built-in output serialization, the sealed result is checked again. This includes CLI scan/snapshot output, JSON serialization through `ScanResult.to_dict()`, text reports, SARIF reports, and snapshot payload/writes. If graph, policy, findings, tools, capabilities, risk, or max severity drift after sealing, output fails closed rather than emitting a trustworthy-looking inconsistent result.

Verified mapping outputs for sealed results are detached from the internal `policy` and `capability_graph` objects before return, preventing post-verification alias mutation from modifying scanner state.

## Compatibility boundary

The seal applies automatically to results returned by `scan()`.

Manually constructed `ScanResult` values remain unsealed by default and retain their existing 1.x library behavior. This is intentional: tests and library consumers may construct partial result objects for formatting or diff fixtures without representing a complete scanner run. The audit does not silently redefine those objects as invalid.

For the same compatibility reason, unsealed manual results preserve their existing mapping-reference behavior. Defensive detachment is limited to scanner-sealed results.

The private seal field is excluded from equality, repr, constructors, and serialized output. Existing stable public keys remain unchanged.

## Regression coverage

Permanent tests cover:

- a real `scan()` result is sealed and passes semantic verification;
- sealing rejects findings that do not match the effective policy;
- sealing rejects capabilities whose tool is absent from discovery;
- resealing with the same effective policy is idempotent while resealing with a different policy is rejected;
- graph mutation after sealing is rejected before JSON serialization;
- policy mutation after sealing is rejected;
- finding mutation after sealing is rejected;
- text, SARIF, and snapshot library serializers reject a mutated sealed result;
- JSON-style and snapshot mapping outputs from sealed results cannot mutate internal policy or graph state through aliases;
- manually constructed unsealed `ScanResult` values keep existing 1.x JSON, text, SARIF, snapshot, and mapping-reference behavior.

## Residual boundary

This is an internal consistency guarantee, not an immutability or runtime-security guarantee. Python callers can deliberately construct unsealed results, and scanner-sealed objects remain ordinary mutable Python objects if callers intentionally mutate the object itself. The guard detects that drift at protected output boundaries; detached outputs prevent accidental or indirect mutation through returned mapping aliases. The scanner still relies on the correctness of its static discovery/classification/policy logic, and the seal does not prove the analyzed agent is safe.

The verification/detachment sequence is designed for normal single-threaded library and CLI use; this audit does not claim transactional atomicity against a hostile concurrent thread mutating the same `ScanResult` during serialization.

No target repository code is imported or executed, no discovered endpoint is contacted, and no credentials are requested or used by this audit.
