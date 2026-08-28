# Release retry and publication transaction

AgentCapDiff treats tag-triggered GitHub Release publication as a fail-closed transaction with explicit retry and ownership rules. The goal is to avoid duplicate publishers, stale drafts, destructive tag cleanup, and accidental deletion of release state created by a different source or actor.

## Transaction identity

The immutable source identity is the tag event's exact `GITHUB_SHA`. A draft created by the reviewed release workflow includes this marker in the release body:

```text
<!-- agentcapdiff-release-source:<40-character-source-sha> -->
```

The marker is an ownership/idempotency discriminator, not a cryptographic signature. Release trust still depends on the strict artifact/attestation verification contract and GitHub reporting the final release immutable.

## Same-tag concurrency

The release workflow uses:

```yaml
concurrency:
  group: release-${{ github.ref }}
  cancel-in-progress: false
```

Only one workflow run for a given tag may actively traverse validation/publication at a time. A duplicate run waits instead of canceling an active publisher. Different tag refs use different concurrency groups and remain independent.

`cancel-in-progress: false` is deliberate: canceling a publisher between draft creation and immutable publication can manufacture a partial state that a replacement run then has to infer.

## Pre-publication remote-state reconciliation

Before build/attestation/publication mutation, the publish job lists releases and then fetches the exact matching release if present. `scripts/release_transaction_state.py` parses bounded JSON and classifies state against the current tag and exact source SHA.

| Remote state | Ownership | Action |
| --- | --- | --- |
| no release | n/a | proceed |
| draft | exact-source marker | delete release object only, preserve tag, retry from clean build |
| published but mutable | exact-source marker | delete release object only, preserve tag, retry from clean build |
| immutable | exact-source marker | mark `already_published=true`; skip all mutating publication steps |
| any release | missing/wrong-source marker | fail closed; do not delete or overwrite |
| malformed/ambiguous JSON | unknown | fail closed |

The release list is used only to establish whether a matching tag exists. If it does, the exact release is fetched again before classification so a stale list result is not treated as sufficient evidence for deletion.

## Idempotent successful retry

If an earlier run already produced an immutable release carrying the exact-source marker, a later same-tag run still performs its validation/CodeQL prerequisites but the publish job treats remote publication as already committed. Build, attestation, draft creation, and publication mutations are skipped.

This is intentionally narrower than "a release with this tag exists." An immutable release without the expected exact-source marker is not silently adopted by the workflow.

## Partial failure cleanup

Draft creation and immutable publication are separate GitHub API operations. The create and publish steps therefore have stable step IDs. If draft creation reported success but the publish step did not succeed, an `always()` cleanup step re-reads remote state and classifies it again.

Cleanup behavior:

- exact-source draft or mutable release: delete the release object only;
- exact-source immutable release: preserve it because publication committed even if a later read/API operation failed;
- missing release: nothing to clean;
- unowned/wrong-source/ambiguous state: fail closed and preserve it for investigation.

The cleanup path never uses `gh release delete --cleanup-tag`. The Git source tag is retained so the reviewed source identity remains inspectable and the production workflow can be safely retried.

## Hard cancellation and uncertain CLI outcomes

A runner can terminate before cleanup executes. A GitHub CLI request can also create a draft server-side and then lose the response, causing the create step to appear failed. In either case, the next serialized run performs the same pre-publication reconciliation. If the residual release carries the exact-source marker, it can be safely cleared or recognized as already immutable.

If the marker is absent, the workflow does not guess that the release belongs to a previous failed run. Manual review is required.

## Race boundary

GitHub Actions concurrency serializes runs of this workflow; it does not lock out privileged maintainers, GitHub Apps, or direct API clients. A privileged actor can still create or alter release state between workflow API calls where GitHub permits it.

The transaction therefore uses a conservative rule: automatic deletion requires an exact-source marker and a fresh state read. Anything else is preserved and treated as a hard failure. This reduces destructive races but is not a distributed transaction or global repository lock.

## Permanent regression controls

`scripts/check_release_transaction_integrity.py` fails CI if the release workflow loses any of these invariants:

- same-tag serialization;
- `cancel-in-progress: false`;
- exact-source state classification;
- idempotency guards on build/attestation/publication mutation steps;
- source-tag-preserving cleanup;
- create → publish → cleanup ordering;
- no `--cleanup-tag` automatic failure path;
- preservation of an already immutable exact-source release.

`tests/test_release_transaction_integrity.py` covers the static contract plus exact-tag matching, duplicate/ambiguous release state, source-marker ownership, draft/mutable/immutable classification, impossible state rejection, and malformed JSON failure.

## Residual trust boundary

The workflow still trusts GitHub Actions concurrency semantics, GitHub Release API state, GitHub CLI behavior, repository write authorization, and GitHub's immutable-release enforcement. The source marker is not an attestation and must not replace verification of `SHA256SUMS`, SBOM, provenance, signer workflow, source ref/commit, signer digest, OIDC identity, and final `isImmutable=true` state.

UNKNOWN or ambiguous remote state is not SAFE and is never auto-deleted.
