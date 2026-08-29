# Policy selector identity audit — 2026-08-29

## Scope

This is one coherent post-v1.0 audit pass covering adversarial policy selector and tool-identity matching:

- `allow_by_tool` identity matching;
- capability selectors used by `deny`, `require_review`, and `scope_constraints`;
- suppression rule/capability/tool selectors;
- trust-boundary tool keys;
- Unicode normalization, case, separator aliases, empty/wildcard-like selectors, and canonical collisions;
- preservation of global policy enforcement when tool identity is ambiguous.

Baseline main before this audit:

`75db08347c08d2a1d7b8bc601ec918b2a238e05d`

The product remains v1.0.0. This pass does not change capability IDs, risk weights, policy precedence, snapshot schema, JSON/SARIF top-level contracts, runtime execution boundaries, or the meaning of a clean scan.

## Finding 1 — raw tool-string equality could silently drop tool-targeted policy

The previous evaluator used exact raw strings for `allow_by_tool` and suppression tool selectors. A policy key such as `repo_tool` therefore did not constrain a semantically equivalent serialized name such as `Repo-Tool`, `repo tool`, or an NFKC-equivalent fullwidth representation.

This created a representation-sensitive policy surface: a name-format change could make a configured per-tool allowlist or narrow suppression selector stop matching without an explicit policy change.

### Remediation

Tool policy identities now use a conservative canonical form:

- Unicode NFKC;
- trim surrounding whitespace;
- case fold;
- collapse runs of whitespace, `_`, and `-` to `_`.

Policy mapping keys are canonicalized at load time and direct `Policy` objects are canonicalized again at evaluation. Multiple raw mapping keys that collapse to the same canonical tool identity fail closed.

## Finding 2 — capability/rule selector spelling was representation-sensitive

Global deny/review selectors, scope-constraint capability keys, and suppression rule/capability selectors were also compared as raw strings. Case/fullwidth aliases could therefore produce different matching behavior despite representing the same normalized security identifier.

### Remediation

Capability and rule selectors use NFKC + trim + case folding. Canonical lowercase ASCII capability IDs remain unchanged. Scope constraints use the same canonical capability identity even for direct `Policy` construction.

Duplicate list entries that canonicalize to the same capability selector deterministically collapse to one selector; mapping collisions remain errors because mapping values could disagree and choosing one would be unsafe.

## Finding 3 — wildcard-looking and unsafe selector text had unclear semantics

Empty mapping keys and values such as `*` or `?` could be parsed as ordinary strings even though the policy model has no wildcard selector contract. Unicode control/format characters could also make review-visible identity differ from matching-visible identity.

### Remediation

Policy identities now fail closed when they are empty, contain control/format/surrogate-category characters, or contain unsupported wildcard-looking syntax (`*`, `?`, `[]`, `{}`).

Optional suppression selectors retain their existing “any” behavior only by omission. Writing a wildcard is rejected rather than guessed.

## Finding 4 — canonical collisions and Unicode ambiguity could hide which tool policy applies

Two observed tool names can collapse to the same canonical identity (`repo-tool` and `Repo Tool`). Conversely, visually similar mixed/Unicode names can remain distinct after safe Unicode normalization, such as a Cyrillic character embedded in an otherwise ASCII-looking name.

Silently choosing a policy interpretation in either situation creates false confidence.

### Remediation

When tool-targeted enforcement is present:

- multiple observed raw names that collapse to one configured canonical identity produce HIGH `policy.tool_identity_collision`;
- a non-ASCII tool identity that cannot be safely matched to configured selectors produces HIGH `policy.tool_identity_ambiguous`;
- these identity-safety findings cannot be suppressed.

The implementation deliberately does not perform fuzzy/confusable-character substitution. Unknown visual similarity is uncertainty, not evidence that two runtime tools are identical.

## Finding 5 — ambiguous runtime tool identity must not bypass global policy

A fail-closed tool-identity parser is useful only if failure does not skip global enforcement. Global deny, scope constraints, and review requirements are capability controls and must remain applicable even when a tool name itself contains unsafe identity characters.

### Remediation

Evaluation now applies global deny before any per-tool identity decision. If runtime tool identity cannot be safely canonicalized, only per-tool matching is unavailable; global capability scope/review controls still run. A regression explicitly verifies that a zero-width character in a tool name cannot bypass a global `shell.execute` deny.

## Regression coverage

Permanent tests cover:

- case/NFKC/common-separator equivalence for tool allowlists;
- NFKC/casefold capability selectors;
- deterministic duplicate capability aliases;
- inherited mapping-key canonical collisions;
- empty and wildcard-like selectors;
- suppression identity equivalence and duplicate canonical selector rejection;
- Cyrillic/ASCII-looking unmatched identity failing closed under tool-targeted policy;
- canonical observed-tool collision producing a non-suppressible HIGH finding;
- policy control/format characters being rejected;
- unsafe runtime tool identity not bypassing global deny;
- direct `Policy` scope constraints using canonical capability identity.

Existing legacy-policy, inheritance, suppression-expiry, policy-weakening, scope, and stable-contract suites remain required green.

## Residual boundary

Canonicalization is intentionally not a general Unicode confusable detector and does not prove runtime object identity. A tool can be renamed to a genuinely different canonical name; static policy cannot infer operator intent for arbitrary renames. Tool-targeted policy should therefore use stable explicit names, and ambiguous Unicode identity remains review-required rather than guessed.

No target repository code is imported or executed by this audit, no discovered endpoint is contacted, and no credentials are requested or used.