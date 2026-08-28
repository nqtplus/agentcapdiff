# Release integrity

AgentCapDiff v0.9 treats the release pipeline as a security boundary. A source tag is not considered a trusted production release merely because a workflow completed or a GitHub Release page exists.

## Trust model

The release input is the exact Git commit referenced by a SemVer tag such as `v0.9.0`. Release jobs never execute code from a scanned target repository. They build AgentCapDiff itself from the tagged source tree and use only reviewed, commit-SHA-pinned GitHub Actions.

For production use, prefer either:

1. a reviewed full AgentCapDiff commit SHA; or
2. an AgentCapDiff release tag that GitHub reports as immutable and whose artifacts/attestations have been verified.

Do not use `@main` as a production trust anchor. Do not move or reuse an existing release tag.

## Release artifacts

The tag-triggered release workflow first removes and recreates the `dist/` and `release/` directories so a tracked/stale file or symlink cannot silently join the release set. The build must then produce exactly the two expected version-matched artifacts: the pure-Python wheel and source distribution. Any missing, extra, symlinked, redirected, or non-regular artifact causes the release metadata step to fail closed.

The workflow then generates:

- `agentcapdiff.spdx.json` — SPDX 2.3 SBOM for the exact validated wheel/source distribution plus declared runtime dependencies;
- `SHA256SUMS` — SHA-256 hashes derived from the same validated artifact reads used by the SBOM;
- GitHub artifact attestations for the built artifacts;
- a GitHub SBOM attestation that binds the SPDX document to those artifacts.

The SBOM/checksum generator rejects symlinked output files and symlink-traversing output directories, pre-validates both auxiliary output destinations, and publishes each metadata file through a same-directory temporary file plus atomic replacement. It does not create arbitrary parent directories. The release workflow uploads exact versioned wheel/sdist paths and exact SBOM/checksum paths rather than a broad publication glob.

The SBOM generator uses `SOURCE_DATE_EPOCH` from the tagged commit when invoked by CI so its creation timestamp is reproducible for the same release input. Artifact hashes remain the authoritative byte-level identity.

## Immutable release rule

Repository administrators must enable GitHub **release immutability** before publishing a production release. The workflow publishes from a draft and immediately checks GitHub's `isImmutable` release property. If GitHub does not report the release as immutable, the workflow fails closed and attempts to remove the mutable release and tag instead of leaving a release that users could mistake for trusted.

This repository-level setting is intentionally treated as external state: source code cannot turn it on by itself. A successful production release therefore requires both the reviewed workflow in this repository and GitHub reporting `isImmutable=true` after publication.

## Least-privilege workflow

The release workflow starts with `permissions: {}` and grants permissions per job:

- validation: `contents: read`;
- CodeQL: read permissions plus `security-events: write`;
- publish: only `contents: write`, `id-token: write`, and `attestations: write`.

Publishing cannot begin until validation and CodeQL succeed. Validation runs the release-integrity checker, Ruff, the complete test suite, the reproducible safety benchmark, and AgentCapDiff's self-policy scan.

## Dependency and Action integrity

All external GitHub Actions under `.github/workflows/` are pinned to full 40-character commit SHAs. Human-readable major-version comments are informational only and are not execution references.

Direct CI/release Python dependencies are reviewed exact pins in `requirements/ci-direct.txt`. The package build backend and declared runtime dependency are also exact-pinned for this release line. Dependabot opens weekly update PRs for both Python and GitHub Actions so moving to a new reviewed SHA/version remains an explicit code-review event.

The `scripts/check_release_integrity.py` gate rejects:

- floating/non-SHA GitHub Action refs;
- `pull_request_target` workflows;
- `write-all` permissions;
- unpinned build dependencies or direct CI dependencies;
- missing Dependabot coverage;
- missing release/SBOM/immutability controls;
- release workflows that omit clean artifact-directory reset, exact build output, validated checksum generation, or exact versioned publication paths;
- broad `sha256sum dist/*` / `dist/* release/*` release patterns;
- a release tag that does not exactly match package/runtime version metadata.

## Verification

Before trusting a release, verify the release is immutable in GitHub, compare downloaded artifact hashes with `SHA256SUMS`, and verify GitHub artifact attestations for the repository/tag. A full commit SHA remains the strongest source-level pin for the composite Action.

A successful attestation proves the artifact was produced by the recorded GitHub Actions workflow identity. It does **not** prove the source code is vulnerability-free or that the scanner can recognize every possible agent capability.

## Compromise and revocation

If a release, workflow credential, dependency pin, Action pin, or maintainer account is suspected to be compromised:

1. stop recommending the affected release immediately;
2. revoke/rotate affected credentials and disable the compromised publication path;
3. publish a security advisory with affected tags, commits, hashes, and attestations when disclosure is safe;
4. do not silently replace artifacts or move an affected immutable tag;
5. ship the fix under a new version/tag after all release gates pass;
6. direct users to a known-good full commit SHA or newer verified immutable release.

If a mutable release was created accidentally, it is not a trusted production release. The v0.9 workflow is designed to delete it and fail rather than accept it.
