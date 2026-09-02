# Audit #32 — Sealed suppression expiry at output boundaries

Date: 2026-09-02

## Scope

Review whether a scanner-sealed `ScanResult` remains safe to serialize after time-dependent temporary policy suppressions expire.

## Finding

Audit #31 enforced suppression expiry when policy findings are evaluated and a result is initially sealed. However, the semantic fingerprint contains static result data only. A sealed result can remain alive in memory after its temporary suppression expires without any field mutation.

Before this audit, `assert_consistent()` revalidated capability projection and fingerprint equality but did not re-check suppression time. Therefore a result sealed while an exception was active could still be serialized later with `policy.suppressed` INFO evidence after the suppression expiry date.

This creates a temporal policy bypass at guarded output boundaries: the exception has expired, but the unchanged sealed object can continue emitting its previously suppressed state.

## Remediation

Add a sealed-result temporal policy check before fingerprint/output validation:

- sealed policy metadata must remain a mapping;
- suppression metadata must remain a list of mappings with ISO expiry dates;
- current date is evaluated in UTC;
- a suppression is valid through its expiry date;
- once `expiry < UTC today`, `assert_consistent()` fails with `ScanResultConsistencyError`;
- because `to_dict()`, report serializers, and `snapshot_payload()` use the guarded consistency boundary, stale sealed output fails closed everywhere.

The semantic fingerprint itself is not rewritten when time advances. Temporal invalidity is an independent invariant, so no mutation is needed to make an expired sealed result unusable.

## Compatibility

Active suppressions and suppressions on their exact expiry date remain serializable. Results without suppressions are unchanged.

Historical snapshot artifacts are intentionally not changed by this audit. A snapshot written while a suppression was valid remains historical evidence and can still be read later; this hardening applies to live sealed `ScanResult` output, not retrospective snapshot interpretation.

No capability inference, risk scoring, policy precedence, public snapshot/JSON/SARIF structure, CLI syntax, package version, target-code execution, endpoint probing, or credential behavior changes.
