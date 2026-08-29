# Release attestation verification

AgentCapDiff release attestations are trusted only when artifact bytes, repository identity, signer workflow, source tag, source commit, signer workflow digest, runner class, and predicate type all match the reviewed release expectation.

A successful signature check by itself is not enough. A valid attestation from another workflow, another tag/ref, or another source commit must not be accepted as evidence for the release being reviewed. A high-assurance consumer must also verify that the current GitHub Release is **published, immutable**, has the expected asset set, and that the tag resolves to the exact reviewed source SHA.

## Required release evidence

For a production release, obtain and review:

- the immutable release tag, for example `v1.0.0`;
- the exact reviewed 40-character source commit SHA the tag is expected to reference;
- `agentcapdiff-<version>-py3-none-any.whl`;
- `agentcapdiff-<version>.tar.gz`;
- `SHA256SUMS`;
- `agentcapdiff.spdx.json`.

Do not infer the source SHA only from an unverified artifact, release body, tag name, or attestation predicate. The reviewed source commit is an independent trust input.

## Recommended online verifier

Place the two package artifacts in one local directory and run the repository verifier from the reviewed AgentCapDiff source commit:

```bash
python scripts/verify_release_attestations.py \
  --tag v1.0.0 \
  --source-sha <reviewed-40-character-source-commit> \
  --dist-dir ./release-download \
  --checksums ./release-download/SHA256SUMS \
  --sbom ./release-download/agentcapdiff.spdx.json \
  --require-published-release
```

With `--require-published-release`, the verifier first queries GitHub and fails closed unless:

- the requested release exists and is not a draft or prerelease;
- GitHub reports `isImmutable=true`;
- the release body carries AgentCapDiff's exact-source marker for the independently reviewed source SHA;
- the published asset set is exactly the wheel, source distribution, `SHA256SUMS`, and `agentcapdiff.spdx.json`;
- the current release tag resolves to the exact reviewed source SHA;
- that source commit remains on the current `main` history.

It then fails closed unless all artifact/provenance requirements below hold:

- `SHA256SUMS` contains exactly the expected wheel and source distribution names;
- both local artifact byte streams match the reviewed SHA-256 manifest;
- the published SPDX 2.3 SBOM lists exactly those two artifacts with the same SHA-256 values;
- GitHub verifies SLSA build provenance for each artifact;
- GitHub verifies the SPDX SBOM attestation for each artifact;
- the attestation certificate/identity matches repository `nqtplus/agentcapdiff`;
- the signer is exactly `nqtplus/agentcapdiff/.github/workflows/release.yml`;
- source ref is exactly `refs/tags/<tag>`;
- source digest and signer-workflow digest both equal the reviewed source commit;
- the OIDC issuer is GitHub Actions;
- self-hosted-runner attestations are rejected;
- the signed SPDX predicate exactly matches the downloaded `agentcapdiff.spdx.json` object.

The script invokes `gh` without a shell and treats missing, malformed, mismatched, or unverifiable evidence as failure. If the GitHub release/tag state cannot be queried, that state is `UNKNOWN`, not safe; do not silently omit `--require-published-release` for an online high-assurance verification.

## Equivalent GitHub CLI attestation policy

The minimum strict identity policy for build provenance is:

```bash
tag=v1.0.0
source_sha=<reviewed-40-character-source-commit>
artifact=agentcapdiff-1.0.0-py3-none-any.whl

gh attestation verify "$artifact" \
  --repo nqtplus/agentcapdiff \
  --signer-workflow nqtplus/agentcapdiff/.github/workflows/release.yml \
  --source-ref "refs/tags/${tag}" \
  --source-digest "$source_sha" \
  --signer-digest "$source_sha" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners \
  --predicate-type https://slsa.dev/provenance/v1
```

Repeat the command for the source distribution.

For the SBOM attestation, use the same identity constraints and require the SPDX predicate type:

```bash
gh attestation verify "$artifact" \
  --repo nqtplus/agentcapdiff \
  --signer-workflow nqtplus/agentcapdiff/.github/workflows/release.yml \
  --source-ref "refs/tags/${tag}" \
  --source-digest "$source_sha" \
  --signer-digest "$source_sha" \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --deny-self-hosted-runners \
  --predicate-type https://spdx.dev/Document/v2.3
```

`--repo` alone is intentionally not the documented high-assurance policy. Repository-only verification can accept a valid signer from another workflow in that repository. Omitting `--source-ref` or `--source-digest` can also allow evidence from a different tag/ref or source commit to be mistaken for the release under review when artifact bytes happen to match. These attestation commands also do not replace the published-release/tag-state checks performed by `--require-published-release`.

## Verified production installation

Verification and installation are separate trust boundaries. After a wheel has passed the checks above, do not hand that verified wheel to an ordinary dependency-resolving install and assume the complete installed environment has the same provenance.

For the reviewed GitHub Action runtime contract — Linux X64 with CPython 3.11, 3.12, or 3.13 — the reviewed source tree includes `requirements/action-runtime-lock.txt`. Install its runtime dependency closure first using the exact hashes already admitted by the project, then install only the verified AgentCapDiff wheel bytes:

```bash
python -m pip --isolated --disable-pip-version-check install \
  --require-hashes --no-deps --no-cache-dir --only-binary=:all: \
  --index-url=https://pypi.org/simple \
  -r requirements/action-runtime-lock.txt

python -m pip --isolated --disable-pip-version-check install \
  --no-deps ./release-download/agentcapdiff-1.0.0-py3-none-any.whl

python -m pip check
```

`--no-deps` is intentional: it prevents a previously verified AgentCapDiff artifact from becoming a trigger for new, dynamically selected package bytes during installation. `pip check` then confirms that the installed environment satisfies the package metadata.

Outside the reviewed Action runtime/platform contract, consumers should maintain an equivalent organization-reviewed, hash-locked dependency set appropriate for their interpreter/platform. Do not weaken `--require-hashes`, accept an unreviewed source distribution, or fall back to floating dependency resolution merely to make installation succeed. If an equivalent dependency provenance set is unavailable, the high-assurance installation state is `UNKNOWN`.

A floating VCS install such as `git+https://github.com/nqtplus/agentcapdiff.git`, `@main`, or an unverified package-index name/version is appropriate only for evaluation/development unless the consumer independently pins and verifies the exact source/artifact/dependency bytes.

## Offline bundle verification

GitHub CLI can download attestation bundles for later offline verification. When verified bundle files are available locally, pass them to the helper:

```bash
python scripts/verify_release_attestations.py \
  --tag v1.0.0 \
  --source-sha <reviewed-40-character-source-commit> \
  --dist-dir ./release-download \
  --checksums ./release-download/SHA256SUMS \
  --sbom ./release-download/agentcapdiff.spdx.json \
  --provenance-bundle ./provenance-bundle.jsonl \
  --sbom-bundle ./sbom-bundle.jsonl
```

The same repository, signer, source-ref, source-digest, signer-digest, predicate, runner, subject-name, and subject-digest requirements are applied when bundles are supplied.

The offline command deliberately does not claim that live GitHub release/tag state was checked. Before treating an offline artifact as a verified production release, retain separately reviewed evidence that the release was published/immutable, carried the exact expected asset set/source marker, and that its tag resolved to the independently reviewed source SHA at the time of acceptance. Missing live or retained release-state evidence is `UNKNOWN`, not safe.

## Why the release workflow self-verifies

The release workflow creates `SHA256SUMS` from the same validated artifact reads used by the SBOM generator. Both the build-provenance and SBOM attestation steps use that manifest through `subject-checksums`, rather than rediscovering subjects with a filesystem glob.

Before any GitHub Release is created, the workflow then runs the same verifier against the generated attestation bundles and the current local wheel/source distribution. That producer-side prepublication invocation intentionally does **not** use `--require-published-release`, because the release does not exist yet. This closes the gap between "an attestation action succeeded" and "the exact artifacts about to be published are bound to the expected repository/workflow/tag/commit and predicate" without creating an impossible circular precondition.

## Residual trust boundary

These checks do not make the hosted environment cryptographically immutable. Verification still depends on GitHub's release/tag APIs, GitHub Actions OIDC identity, GitHub/Sigstore trusted roots, the GitHub CLI verifier, DNS/TLS/network availability, and the integrity of the independently reviewed release workflow/source SHA. A signed predicate can only be as trustworthy as the workflow authorized to produce it.

Attestation verification proves constrained provenance and subject binding. Release-state verification proves the observed GitHub state at verification time. Neither proves that AgentCapDiff is vulnerability-free or that a static scan proves an agent is safe.
