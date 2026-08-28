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

Every `actions/checkout` step in repository workflows explicitly sets `persist-credentials: false`. The checkout token is therefore not intentionally stored in repository Git configuration for later shell/build/test steps; checkout post-job cleanup is defense in depth rather than the primary credential-removal boundary. Release API operations that genuinely require write authority receive `${{ github.token }}` only as step-scoped `GH_TOKEN` environment input to the relevant `gh` commands.

Publishing cannot begin until validation and CodeQL succeed. Validation runs the release-integrity checker, Ruff, the complete test suite, the reproducible safety benchmark, and AgentCapDiff's self-policy scan.

## Dependency, Python, runner, and Action integrity

All external GitHub Actions under `.github/workflows/` are pinned to full 40-character commit SHAs. Human-readable major-version comments are informational only and are not execution references.

`requirements/ci-direct.txt` records the reviewed direct CI/release dependencies. `requirements/ci-lock.txt` is the actual install source and freezes the complete currently required dependency closure. Every dependency is an exact `name==version` pin and every accepted wheel byte stream is bound to an explicit SHA-256. Compiled packages list only the Ubuntu x86-64 wheels required by CPython 3.11.16, 3.12.14, and 3.13.15; source distributions and unreviewed platform wheels are not accepted.

CI/release workflows install with pip isolated mode, `--require-hashes`, `--no-deps`, `--no-cache-dir`, `--only-binary=:all:`, an explicit `https://pypi.org/simple` index, and the pip version check disabled. Resolver/cache drift is removed from this dependency-install boundary, source distributions cannot execute as a fallback, and downloaded dependency bytes must match the reviewed hashes. `python -m pip check` then fails if the frozen closure is incomplete or incompatible.

`requirements/ci-environment.json` records the reviewed GitHub-hosted execution environment. Workflows use `ubuntu-24.04` rather than the moving `ubuntu-latest` alias, setup-python requests exact patch versions, and every job runs `scripts/check_ci_environment.py` before build/test/security work. The probe checks GitHub-hosted runner identity, Linux/x64, Ubuntu 24.04, the reviewed `ImageOS`/`ImageVersion`, and the expected Python and pip versions.

The current runner image review point is Ubuntu 24.04 image `20260823.283.1`. GitHub does not provide a `runs-on` syntax that selects an immutable image digest or exact image build. The provenance check therefore acts as a post-scheduling allowlist: if GitHub advances the hosted image, the job fails closed until that new image is reviewed and `ci-environment.json` is updated. This is stronger than accepting `ubuntu-latest`, but it is not equivalent to a cryptographically pinned VM image.

The setup-python Action itself is commit-SHA pinned, exact Python patches `3.11.16`, `3.12.14`, and `3.13.15` are selected, and the observed toolcache pip bootstrap is explicitly allowlisted at `26.2.1`. Jobs that intentionally use the runner's ambient Python separately verify Python `3.12.3` and pip `24.0`. A version allowlist does not cryptographically pin the Python or pip executable bytes, so the hosted toolcache/runner remains an external trust boundary. Dependency SHA-256 verification protects package artifact bytes only to the extent that this local pip verifier correctly performs hash verification. PyPI remains an availability/metadata dependency, although a substituted package artifact cannot pass `--require-hashes` without a reviewed digest.

Dependabot opens weekly update PRs for both Python and GitHub Actions so moving to a new reviewed dependency version, closure, artifact hash, or Action SHA remains an explicit code-review event. Changes to the reviewed runner/Python/pip provenance file are likewise expected to be deliberate review events when the hosted environment moves.

The `scripts/check_release_integrity.py` gate rejects:

- floating/non-SHA GitHub Action refs;
- any `actions/checkout` step that does not explicitly set `persist-credentials: false`;
- `pull_request_target` workflows;
- `write-all` permissions;
- non-exact, remote, conditional, duplicate, unhashed, non-SHA-256, or direct/lock-mismatched CI dependency pins;
- a lock that does not extend beyond the direct dependency set;
- workflow use of `requirements/ci-direct.txt` as an install source;
- setup-python pip caching for locked CI/release dependency installs;
- dependency installs that differ from the isolated, hash-required, no-deps, no-cache, binary-only, explicit-index contract or omit a matching `pip check`;
- moving runner aliases or workflows that do not verify the reviewed runner provenance once per job;
- setup-python versions that do not use reviewed exact patch versions;
- setup-python jobs that do not verify the reviewed pip bootstrap version;
- ambient-Python jobs that do not verify the reviewed Python and pip versions;
- missing Dependabot coverage;
- missing release/SBOM/immutability controls;
- release workflows that omit clean artifact-directory reset, exact build output, validated checksum generation, or exact versioned publication paths;
- broad `sha256sum dist/*` / `dist/* release/*` release patterns;
- a release tag that does not exactly match package/runtime version metadata.

## Verification

Before trusting a release, verify the release is immutable in GitHub, compare downloaded artifact hashes with `SHA256SUMS`, and verify GitHub artifact attestations for the repository/tag. A full commit SHA remains the strongest source-level pin for the composite Action.

A successful attestation proves the artifact was produced by the recorded GitHub Actions workflow identity. It does **not** prove the source code is vulnerability-free, that the hosted runner/Python/pip executables are cryptographically immutable, or that the scanner can recognize every possible agent capability.

## Compromise and revocation

If a release, workflow credential, dependency pin/hash, Action pin, runner image, Python/pip bootstrap, or maintainer account is suspected to be compromised:

1. stop recommending the affected release immediately;
2. revoke/rotate affected credentials and disable the compromised publication path;
3. publish a security advisory with affected tags, commits, hashes, and attestations when disclosure is safe;
4. do not silently replace artifacts or move an affected immutable tag;
5. ship the fix under a new version/tag after all release gates pass;
6. direct users to a known-good full commit SHA or newer verified immutable release.

If a mutable release was created accidentally, it is not a trusted production release. The v0.9 workflow is designed to delete it and fail rather than accept it.
