# Static capability scope evidence

AgentCapDiff v0.2 keeps existing capability IDs and attaches separate static scope evidence to filesystem and external-network capabilities.

## Scope kinds

- `restricted`: a finite path/domain/URL constraint is visible in static tool metadata and can be normalized conservatively.
- `broad`: static metadata explicitly permits filesystem-root-wide or arbitrary network access.
- `unknown`: the effective scope cannot be established from static input. Unknown is never treated as restricted or safe.

## Filesystem scope

Known path literals may come from schema `const`, `enum`, `default`, or `examples` fields associated with path-like properties, or from narrowly worded descriptions. `..` traversal, template/dynamic markers, malformed values, and unconstrained string paths remain `unknown`. Root-wide markers such as `/`, `/**`, `*`, or `**` normalize to broad `/**`.

This is evidence about declared metadata only. AgentCapDiff does not execute tool code, resolve runtime configuration, inspect credentials, or prove that an implementation enforces the declared path restriction.

## Network scope

Exact HTTP(S) URLs, exact domains, and wildcard domain families such as `*.example.com` can be represented as restricted static evidence. Arbitrary/wildcard destinations normalize to broad `*`. Free-form URL/domain fields and dynamic/template destinations remain `unknown`.

AgentCapDiff never resolves DNS and never contacts a discovered endpoint. Static scope is not runtime network enforcement; redirects, proxies, DNS behavior, implementation bugs, and configuration outside the scanned schema may widen effective access.

## Diff behavior

Snapshots retain scope evidence separately from the stable capability fingerprint. Diffs report scope changes and flag a proven expansion only when static evidence establishes it, such as `./reports/**` → `/**` or an exact domain allowlist → `*`.

Changes involving `unknown` are shown as changes but are not falsely labeled proven expansions because the base effective scope was not known.

## False positives and false negatives

Static analysis can miss restrictions implemented only in code or runtime policy, and it can report broad/unknown metadata even when runtime controls are tighter. Conversely, declared restrictions may not be enforced correctly by the implementation. Treat scope output as review evidence, not an authorization guarantee.
