# Audit #38 — Policy record selector validity

## Scope

Prevent direct-library `policy_to_record()` from emitting selector forms that the policy evaluator itself rejects.

## Finding

Audits #36 and #37 bound serializer container and suppression semantics, but other security-relevant selectors could still be recorded before evaluator canonicalization rejected them.

Examples included:

- wildcard deny/review/allowlist selectors;
- unsafe control/format characters in capability selectors;
- two tool spellings that collapse to the same canonical tool identity;
- two scope-constraint keys that collapse to the same canonical capability identity.

A direct caller could therefore produce machine-readable policy metadata from a `Policy` object that was not a valid effective policy for enforcement.

## Remediation

`policy_to_record()` now performs validation-only calls through the same selector helpers used by `evaluate_policy()`:

- validate every `deny` capability selector;
- validate every `require_review` capability selector;
- run `_canonical_policy_allowlists(policy)` to validate tool/capability selectors and canonical tool collisions;
- run `_canonical_scope_constraints(policy)` to validate constrained capability selectors and canonical collisions;
- retain the Audit #37 suppression validation pass.

The canonicalized results are deliberately discarded. Valid direct-library spelling remains unchanged in the serialized record in this audit.

## Regression coverage

Permanent tests cover:

- wildcard deny rejection;
- control/format review selector rejection;
- wildcard allowlist capability rejection;
- colliding tool aliases rejection;
- colliding scope-constraint aliases rejection;
- unchanged raw spelling for valid non-canonical direct-library selectors.

## Security effect

The machine-readable serializer can no longer publish enforced policy selectors that the evaluator considers syntactically unsafe or identity-ambiguous. Serializer acceptance now better matches enforcement acceptance without yet changing record normalization semantics.

## Residual boundary

Valid non-canonical selector spelling can still be serialized as supplied while evaluation uses canonical identities. That means two semantically equivalent direct policies can still produce different policy records and policy-diff results. Canonical identity binding remains a separate audit because it intentionally changes direct-library record normalization.

Trust-boundary tool keys are informational policy metadata rather than enforcement selectors in the current evaluator and are not changed by this audit; their identity semantics should be assessed alongside broader record canonicalization.

## Non-goals

This audit does not change policy precedence, selector matching, valid direct-library record spelling, suppression behavior, capability inference, risk scoring, YAML syntax, snapshot schema, CLI syntax, package version, target-code execution, endpoint probing, credentials, or historical snapshot behavior.
