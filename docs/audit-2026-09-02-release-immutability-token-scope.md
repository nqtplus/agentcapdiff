# Audit #43 — Release immutability token scope

Date: 2026-09-02

## Finding

The first `v1.0.0` production-tag run passed all three release validation matrices and CodeQL, then failed before artifact build in the publish job.

The failing step called GitHub's repository `immutable-releases` settings endpoint with the workflow `${{ github.token }}`. GitHub returned `HTTP 403 Resource not accessible by integration`.

That endpoint is a repository-administration settings read. The release workflow intentionally grants only `contents: write`, `id-token: write`, and `attestations: write` to the publish job, so the least-privilege Actions token cannot perform that administration read.

This was an authorization mismatch in the release control itself, not evidence that release immutability was disabled.

## Security impact

The mismatch blocked production publication even after the release gate was green. A tempting workaround would be to add an administrator PAT or another broad credential to the release workflow, which would enlarge the release trust boundary and create a more valuable secret in CI.

No `v1.0.0` wheel, source distribution, checksum manifest, SBOM, attestation, draft release, or published GitHub Release was created. The workflow failed before those steps.

The source tag `v1.0.0` remains pinned to reviewed commit `f5ff28757aa1f1678483267e6c57e747cd04d9ed`. It is retained as audit history and must not be moved or reused.

## Fix

The release workflow no longer probes the administration-only repository settings endpoint with `GITHUB_TOKEN`.

Repository release immutability remains an external maintainer precondition. The workflow still:

1. runs the complete release validation matrix and CodeQL before publication;
2. builds and attests only from the exact tagged source;
3. creates a workflow-owned draft with the exact-source marker;
4. publishes the draft;
5. immediately requires GitHub to report `isImmutable=true`;
6. fails closed if immutable state is not reported; and
7. re-reads and removes only exact-source workflow-owned draft/mutable release state while preserving the source tag.

No administrator PAT or additional privileged secret is introduced.

## Regression coverage

`tests/test_release_integrity.py` now asserts that:

- the release workflow does not call `repos/$GITHUB_REPOSITORY/immutable-releases`;
- publication still explicitly changes the draft to published state;
- the workflow reads `isImmutable` from the published release; and
- a non-immutable result remains a hard failure.

The package/runtime patch version is advanced to `1.0.1` so the failed `v1.0.0` source tag is never moved or reused.

## Release disposition

`v1.0.0` is a failed pre-publication source tag with no GitHub Release or release assets. `v1.0.1` is the repaired production publication candidate and must pass the normal protected-main PR gates and the full tag-triggered release workflow before it is accepted as a production release.
