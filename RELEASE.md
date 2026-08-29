# Release verification

A release is complete only after its roadmap items, release gate, version metadata, documentation, issue states, and required GitHub checks agree on `main`.

## v1.0 stable release checklist

Before declaring `1.0.0` stable and merging the release PR:

- package version and runtime `__version__` are identical and finalized at `1.0.0`;
- ROADMAP marks every v1.0 item complete and the heading carries the completion marker;
- README, CHANGELOG, SECURITY, release guidance, stability contract, and verification record agree on the stable state;
- stable capability/policy compatibility guarantees and JSON/SARIF machine-readable contracts have regression coverage;
- supported static framework adapters pass cross-framework conformance without importing/executing target code;
- semantic filesystem/network scope and conservative capability-path regression suites are green;
- CI passes on Python 3.11, 3.12, and 3.13, including Ruff, full pytest, the safety benchmark regression gate, and release-integrity regression gate;
- CodeQL passes;
- AgentCapDiff self-policy passes;
- PR capability diff and project-state consistency pass;
- no known unresolved critical/high AgentCapDiff vulnerability exists in the repository issue tracker at final verification;
- issue #27 acceptance criteria are complete and the issue is closed/completed only after the final PR head is green.

The final merged `main` must then be re-read to verify the expected ROADMAP checkbox state, `1.0.0` package/runtime version, README stable status, CHANGELOG entry, security/support policy, and merged SHA are actually present.

## Production tag and immutability

After the merged commit is selected for a production tag, the tag must be exactly `v<package-version>` and point to a commit on `main`. Repository release immutability must be enabled before a production release tag is published.

The tag-triggered release workflow re-runs validation and CodeQL before publication. A production release is accepted only when GitHub reports `isImmutable=true`. If publication reaches a mutable/draft partial state, the workflow removes only a release state that carries AgentCapDiff's exact-source ownership marker and preserves the source tag for a safe retry; it never uses `--cleanup-tag` as automatic failure cleanup.

The merge of v1.0 source state and the publication of an immutable GitHub Release are separate events: source state may be marked stable only after the PR release gate passes, while a production release asset/tag is trusted only after the tag workflow and immutable-release verification pass.

## Release workflow output

A successful tag-triggered release creates:

- wheel and source distribution;
- `SHA256SUMS` for built artifacts;
- `agentcapdiff.spdx.json` SPDX 2.3 SBOM;
- GitHub build-provenance attestation for the exact checksum-manifest subjects;
- GitHub SPDX SBOM attestation bound to the same subjects;
- an immutable GitHub Release.

Both attestation steps consume `release/SHA256SUMS` via `subject-checksums`, so subject identity comes from the same validated artifact hashes used for release metadata rather than a second filesystem glob.

Before `gh release create` runs, the publish job verifies the generated attestation bundles against the local wheel/source distribution and published SBOM. The verification must constrain repository `nqtplus/agentcapdiff`, signer workflow `nqtplus/agentcapdiff/.github/workflows/release.yml`, the exact release tag ref, exact source commit, signer workflow digest, GitHub Actions OIDC issuer, GitHub-hosted runner class, and exact predicate type. The verified artifact subject name/digest must match the checksum manifest; the SPDX predicate must equal the `agentcapdiff.spdx.json` asset to be published.

The workflow starts with `permissions: {}` and grants only per-job permissions. Validation and CodeQL must finish successfully before the publish job receives write/attestation permissions.

## Retry, partial failure, and idempotency

Release publication is treated as a small transaction rather than a one-shot series of unrelated commands. Runs for the same tag are serialized with a GitHub Actions concurrency group and are not canceled by a later duplicate run. Different tags remain independent.

A draft created by the workflow contains an exact-source marker of the form `<!-- agentcapdiff-release-source:<40-char-source-sha> -->`. Before mutating release state, a retry classifies any existing release for the tag:

- no release: proceed normally;
- workflow-owned draft or mutable partial release for the same source SHA: delete the release object only, preserve the tag, and rebuild/re-attest from the reviewed source;
- workflow-owned immutable release for the same source SHA: treat the retry as an idempotent already-complete publication and skip mutating publication steps;
- any release without the exact-source marker, or with a marker for a different source SHA: fail closed and do not delete or overwrite it.

If draft creation succeeded but publication fails, an `always()` cleanup step re-reads the remote release state before deleting anything. It removes only workflow-owned draft/mutable partial state for the same exact source commit. If publication actually reached an immutable release before a later API/read failure, cleanup preserves it; the next retry recognizes the immutable release as already complete.

A hard runner termination can still prevent in-run cleanup. The next serialized retry performs the same ownership/state reconciliation. Automatic failure handling never deletes the Git source tag, which keeps the reviewed source identity available for investigation and retry.

These controls reduce duplicate-run, partial-response, and workflow-retry hazards; they do not make GitHub's release service transactional or eliminate races with privileged manual/API actors. Unowned/ambiguous remote state therefore remains fail-closed rather than being auto-deleted. See `docs/release-retry-transaction.md` for the detailed state machine.

## Consumer release and attestation verification

Do not accept a production artifact merely because `gh attestation verify <artifact> --repo nqtplus/agentcapdiff` succeeds. Repository-only identity is intentionally broader than the release trust policy.

For online production verification, run `scripts/verify_release_attestations.py` from the independently reviewed source commit and add `--require-published-release`. The consumer verification must establish all of these together:

- local wheel/source bytes match `SHA256SUMS`;
- SPDX metadata matches those exact bytes;
- provenance and SPDX attestations bind the exact repository, signer workflow, source ref, source commit, signer digest, runner class, and predicate type;
- the observed GitHub Release is published, non-prerelease, and immutable;
- the release contains exactly the expected four assets and the exact-source ownership marker;
- the current release tag still resolves to the independently reviewed source SHA;
- that source commit remains on the current `main` history.

Example:

```bash
python scripts/verify_release_attestations.py \
  --tag v1.0.0 \
  --source-sha <reviewed-40-character-source-commit> \
  --dist-dir ./release-download \
  --checksums ./release-download/SHA256SUMS \
  --sbom ./release-download/agentcapdiff.spdx.json \
  --require-published-release
```

The exact reviewed source commit SHA is an independent trust input. Do not derive it solely from an unverified release artifact, tag name, release body, or workflow-controlled predicate metadata. If published-release or tag state cannot be verified, treat it as `UNKNOWN`, not safe.

Producer-side prepublication self-verification deliberately omits `--require-published-release` because the GitHub Release does not exist yet; the workflow later requires GitHub to mark the published release immutable.

## Verified production installation

A verified package artifact can still lose its provenance boundary if ordinary `pip` dependency resolution is allowed to fetch new, unreviewed bytes during installation.

For the reviewed Linux X64 / CPython 3.11–3.13 Action runtime, first install the exact SHA-256-locked runtime dependency set from `requirements/action-runtime-lock.txt`, then install the already-verified AgentCapDiff wheel with `--no-deps`, and finish with `pip check`:

```bash
python -m pip --isolated --disable-pip-version-check install \
  --require-hashes --no-deps --no-cache-dir --only-binary=:all: \
  --index-url=https://pypi.org/simple \
  -r requirements/action-runtime-lock.txt

python -m pip --isolated --disable-pip-version-check install \
  --no-deps ./release-download/agentcapdiff-1.0.0-py3-none-any.whl

python -m pip check
```

For another supported local platform/interpreter, use an equivalent organization-reviewed dependency lock with exact hashes. Do not relax hash verification or silently re-enable dynamic dependency resolution if an appropriate lock is unavailable; that installation state remains `UNKNOWN`.

## Production pinning

For the composite GitHub Action, a reviewed full commit SHA is the strongest source-level production pin:

```yaml
- uses: nqtplus/agentcapdiff@<reviewed-full-commit-sha>
```

A reviewed verified immutable release tag may also be used where that release, checksums, SBOM, strict attestations, current tag binding, and exact source SHA have been verified. Do not rely on `@main` for production. Never move or reuse a released version tag.

For CLI/package installation, floating VCS sources such as `git+https://github.com/nqtplus/agentcapdiff.git`, unverified tags, or a package-index name/version alone are evaluation/development conveniences rather than high-assurance production provenance.

## Historical v0.9 release gate

v0.9 established the supply-chain baseline carried into 1.x: exact Action/dependency pins, benchmark/release-integrity gates, SPDX SBOM, checksums, attestations, least-privilege workflow permissions, immutable release enforcement, and parser/path/output/CI trust-boundary review.

See `docs/stability-v1.0.md` for 1.x compatibility guarantees, `docs/v1.0-verification.md` for the stable-release evidence map, `docs/release-integrity.md` for the complete release trust model, `docs/attestation-verification.md` for strict attestation/release-state verification and replay/misbinding resistance, and `docs/release-retry-transaction.md` for release retry/idempotency behavior.
