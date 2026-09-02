# Audit #37 — Policy record suppression semantic binding

## Scope

Bind direct-library `policy_to_record()` suppression output to the same suppression validity rules already enforced by the policy evaluator.

## Finding

Audit #36 made the policy serializer reject malformed container shapes, but a `Suppression` instance was still considered recordable without validating its inner semantics.

That left several inconsistent paths:

- an expired direct suppression could still be emitted into machine-readable policy metadata even though `evaluate_policy()` rejects it;
- an empty reason or rule ID could be serialized even though it is not a valid effective exception;
- invalid expiry types such as `datetime` or `str` could reach `.isoformat()`/sorting and fail through incidental runtime behavior;
- malformed optional selectors or duplicate canonical suppression selectors could be recorded even though the evaluator rejects them.

## Remediation

- reuse `_canonical_suppressions(policy)` as a validation pass before policy serialization;
- reject expired suppressions using current UTC date;
- require non-empty rule ID and reason;
- require expiry to be a `date` and not a `datetime` subclass;
- require valid optional capability/tool selectors and reject unsupported wildcards;
- reject duplicate canonical suppression selector tuples;
- intentionally discard the canonicalized copy so this audit does not rewrite the serializer's existing direct-library spelling/output representation.

## Regression coverage

Permanent tests cover:

- expired direct suppression rejection;
- validity through the exact expiry date;
- empty reason/rule ID rejection;
- invalid `datetime`/string expiry rejection;
- blank capability and wildcard tool selector rejection;
- duplicate canonical suppression selector rejection;
- unchanged raw spelling/reason representation for a valid direct policy record.

## Security effect

The machine-readable policy serializer can no longer publish a temporary exception that the enforcement engine considers invalid or expired. Direct policy metadata and effective suppression validity now share the same acceptance boundary.

## Residual boundary

This audit validates suppression semantics but deliberately does not canonicalize serialized selector spelling. More broadly, valid direct-library policy selectors can still be serialized in caller-provided spelling while evaluation uses canonical identities. That identity-binding question remains a separate audit because changing record normalization can affect direct-library output semantics and policy diffs.

## Non-goals

This audit does not change policy precedence, suppression matching behavior, selector canonicalization in output, capability inference, risk scoring, YAML syntax, snapshot schema, CLI syntax, package version, target-code execution, endpoint probing, credentials, or historical snapshot behavior.
