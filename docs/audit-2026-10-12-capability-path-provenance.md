# AUDIT #19 — Capability path evidence provenance follow-up

Date: 2026-10-12 (Asia/Ho_Chi_Minh)

## Baseline and scope

Fresh-read of `main` found SHA `2499239a992e0b91a78c96dc516826abc5dd4858`, package version `1.0.1`, and an existing open PR #79. The repository already contains an earlier capability graph/path audit record at `docs/audit-2026-08-29-capability-path-composition.md`; this follow-up does not repeat its previously remediated findings.

This pass checked path evidence construction and its graph regression tests, focusing on whether multiple tools/schemas/sources remain distinguishable after evidence normalization and deduplication. No target code was executed or imported.

## Finding — source provenance could be lost during evidence deduplication

`build_capability_graph()` collects rendered evidence in a set. Before this change, each evidence string included capability ID, tool display name, scope, and confidence, but omitted both `Capability.source` and the source/adapter/signal fields of `CapabilityEvidence`.

Consequently, otherwise-identical capability observations contributed by different serialized schema sources could collapse into the same reviewer-facing string. The path itself was still emitted and this observation alone did not demonstrate a severity downgrade or a false-safe classification; the demonstrated concern is loss of source attribution in reviewer evidence.

## Remediation proposed on this branch

- Include the capability source in each rendered path evidence record, using `not established` when absent.
- Preserve adapter-level evidence source and signal when present.
- Add a regression test with two sources contributing the same normalized capability and tool.
- Document the provenance behavior without changing capability IDs, path rule IDs, graph schema version, risk weights, policy semantics, or the static-only trust boundary.

## Validation and state limitations

The regression test was added but has not been executed locally; the repository's safety instructions prohibit importing or executing the target code during this audit. GitHub PR checks are the validation gate. At the time of the fresh-read, the most recent PR #79 checks failed at runner-provenance verification before normal test/security steps ran. Those failures must not be treated as results for this branch or bypassed.

Google Sheets state could not be read through the currently available connected tools in this session. Therefore the Control row and Daily Log deduplication/reconciliation remain UNKNOWN until that surface is accessible. This record alone does not mean the audit is COMPLETE.
