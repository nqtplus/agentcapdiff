# Audit #22 — Capability inference binding

## Scope

This audit checks whether a scanner-sealed `ScanResult` proves that its `capabilities` are actually derived from the discovered `ToolRecord` evidence that the scanner holds, including nested `input_schema` evidence and the post-bootstrap duplicate-scope reconciliation stage.

The audit does not change capability rules, risk weights, policy precedence, snapshot schema, public JSON/SARIF output, or the no-schema-leak contract.

## Finding

Audit #21 sealed the consistency of capabilities, graph, policy, findings, risk, and output boundaries, but the semantic validator only required each capability to reference a discovered tool name. It did not recompute capability inference from the discovered tools.

`ToolRecord` is frozen, but its `input_schema` field is a mutable nested dictionary. Capability inference reads this schema for property, action, text, and scope signals. The Audit #21 semantic fingerprint intentionally serialized only public tool fields and omitted `input_schema` because public output must not leak raw schemas.

That left two related gaps for sealed results:

1. a capability record could reference a real discovered tool name while not matching the capability set that `infer_capabilities()` plus `reconcile_capability_scopes()` would derive from that tool evidence;
2. nested `input_schema` could be mutated after sealing without changing the previous semantic fingerprint. If the mutation changed inference, the stored capability set could become stale. Even if the mutation did not currently change inference, the evidence backing the seal had still changed.

## Remediation

The sealed-result validator now recomputes the scanner pipeline exactly:

`reconcile_capability_scopes(infer_capabilities(result.tools))`

and requires the recomputed capability records to equal `result.capabilities` before graph/snapshot validation proceeds.

The private semantic fingerprint now also incorporates each tool's `input_schema`. This is internal-only evidence binding: `ScanResult.to_dict()`, snapshots, text output, and SARIF continue to omit raw input schemas, preserving the existing no-schema-leak and v1.0 public-output contracts.

The existing fast failure for capabilities that reference absent tool names remains in place so that diagnostic behavior stays precise.

## Permanent regressions

Tests now cover:

- a fabricated capability that names a real discovered tool but is not derivable from that tool's evidence is rejected at seal time;
- duplicate provenance remains valid when capabilities are produced by real inference and conservative scope reconciliation;
- mutating nested schema evidence after sealing so that inference changes is rejected before serialization;
- mutating nested schema evidence after sealing in a way that leaves current inference unchanged is still rejected by the private semantic fingerprint;
- unsealed manually constructed 1.x `ScanResult` objects retain their historical library behavior;
- public output continues to avoid exposing `input_schema`.

## Security effect

For scanner-sealed results, the semantic chain is now bound end-to-end:

`discovered ToolRecord evidence -> capability inference -> conservative scope reconciliation -> graph -> policy findings -> serialized outputs`

A sealed result can no longer claim a capability set that is merely self-consistent downstream but unsupported by its own discovered tool evidence.

## Residual boundaries

This remains an in-process consistency guarantee, not a Python object sandbox. Deliberate private-attribute manipulation or hostile concurrent mutation is outside the claimed boundary. Unsealed manual library objects remain intentionally permissive for 1.x compatibility.

No target repository code is imported or executed, no discovered endpoint is contacted, and no credentials are requested or used by this audit.
