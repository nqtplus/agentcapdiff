# Audit 2026-08-28 — release partial failure, retry, idempotency, and race boundary

## Scope

Exactly one AUDIT pass covering tag-triggered release partial failure, workflow retry/idempotency, draft/published cleanup, source-tag preservation, and same-tag race boundaries.

This pass reviewed only AgentCapDiff's own release workflow and supporting integrity controls. It did not execute/import scanned target repository code, probe discovered endpoints, collect credentials, or expand release permissions.

## Findings

1. The release workflow had no same-tag concurrency group. Duplicate/retried tag runs could overlap validation/publication and race on the same GitHub Release.
2. A successful draft creation followed by a failed publish/immutability check could leave a stale draft. A later run would collide with the existing release instead of reconciling partial state.
3. The previous non-immutable cleanup used `gh release delete ... --cleanup-tag`, which coupled release-object cleanup to deletion of the source tag. That made retry/investigation more destructive than necessary and removed the source identity used to trigger the workflow.
4. There was no explicit idempotent terminal state. A retry after a successful immutable publication would attempt to rebuild/create the same release instead of recognizing an already committed exact-source release.
5. Automatic cleanup did not distinguish workflow-owned same-source partial state from release state created by another source/actor. This left a destructive race boundary if cleanup logic were broadened without ownership checks.

## Fix

- Added workflow-level same-tag concurrency using `release-${{ github.ref }}` with `cancel-in-progress: false`.
- Added `scripts/release_transaction_state.py`, a bounded fail-closed JSON classifier for exact-tag presence and exact-source release ownership/state.
- Draft releases now carry `<!-- agentcapdiff-release-source:<source-sha> -->` as an idempotency/ownership marker.
- Before publication mutation, the workflow re-reads release state:
  - missing → proceed;
  - exact-source draft/mutable partial state → delete release object only and retry;
  - exact-source immutable state → mark already published and skip mutation;
  - unowned/wrong-source/ambiguous state → fail closed without deletion.
- All build, SBOM, attestation, verification, draft-create, and publish mutation steps are guarded by the idempotent terminal-state output.
- Publish failure no longer deletes the tag. A dedicated cleanup step reclassifies remote state and removes only exact-source draft/mutable release objects while preserving immutable state and the source tag.
- Added `scripts/check_release_transaction_integrity.py` plus regression coverage and CI/release-integrity/release-validation gates.
- Added production guidance in `RELEASE.md` and `docs/release-retry-transaction.md`.

## Compatibility

Package/runtime remains `1.0.0`. Capability schema, policy semantics, JSON/SARIF, snapshot, diff, benchmark, CLI, and static-analysis safety contracts are unchanged. Release permissions remain least-privilege and unchanged.

## Residual risk

GitHub Actions concurrency is not a global lock against privileged maintainers, Apps, or API clients. GitHub Release API/CLI, hosted runners, and immutable-release enforcement remain external trust boundaries. A hard runner termination may still leave partial state until the next retry reconciles it. The exact-source marker is an ownership/idempotency discriminator, not a cryptographic signature or substitute for release attestation verification.

UNKNOWN/ambiguous remote state remains fail-closed and is never treated as SAFE.
