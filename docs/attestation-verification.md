# Release attestation verification

AgentCapDiff release attestations are trusted only when artifact bytes, repository identity, signer workflow, source tag, source commit, signer workflow digest, runner class, and predicate type all match the reviewed release expectation.

A successful signature check by itself is not enough. A valid attestation from another workflow, another tag/ref, or another source commit must not be accepted as evidence for the release being reviewed.

## Required release evidence

For a production release, obtain and review:

- the immutable release tag, for example `v1.0.0`;
- the exact reviewed 40-character source commit SHA the tag is expected to reference;
- `agentcapdiff-<version>-py3-none-any.whl`;
- `agentcapdiff-<version>.tar.gz`;
- `SHA256SUMS`;
- `agentcapdiff.spdx.json`.

Do not infer the source SHA only from an unverified artifact. The reviewed source commit is an independent trust input.

## Recommended verifier

Place the two package artifacts in one local directory and run the repository verifier from the reviewed AgentCapDiff source commit:

```bash
python scripts/verify_release_attestations.py \
  --tag v1.0.0 \
  --source-sha <reviewed-40-character-source-commit> \
  --dist-dir ./release-download \
  --checksums ./release-download/SHA256SUMS \
  --sbom ./release-download/agentcapdiff.spdx.json
```

The verifier fails closed unless all of the following hold:

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

The script invokes `gh attestation verify` without a shell and treats missing, malformed, mismatched, or unverifiable evidence as failure.

## Equivalent GitHub CLI policy

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

`--repo` alone is intentionally not the documented high-assurance policy. Repository-only verification can accept a valid signer from another workflow in that repository. Omitting `--source-ref` or `--source-digest` can also allow evidence from a different tag/ref or source commit to be mistaken for the release under review when artifact bytes happen to match.

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

## Why the release workflow self-verifies

The release workflow creates `SHA256SUMS` from the same validated artifact reads used by the SBOM generator. Both the build-provenance and SBOM attestation steps use that manifest through `subject-checksums`, rather than rediscovering subjects with a filesystem glob.

Before any GitHub Release is created, the workflow then runs the same verifier against the generated attestation bundles and the current local wheel/source distribution. This closes the gap between "an attestation action succeeded" and "the exact artifacts about to be published are bound to the expected repository/workflow/tag/commit and predicate."

## Residual trust boundary

These checks do not make the hosted environment cryptographically immutable. Verification still depends on GitHub Actions OIDC identity, GitHub/Sigstore trusted roots, the GitHub CLI verifier, and the integrity of the reviewed release workflow. A signed predicate can only be as trustworthy as the workflow authorized to produce it.

Attestation verification proves constrained provenance and subject binding. It does not prove that AgentCapDiff is vulnerability-free or that a static scan proves an agent is safe.
