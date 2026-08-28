# Audit 2026-08-28 — release attestation identity and binding

## Scope

Exactly one AUDIT pass covering release attestation/provenance subject identity, artifact/source binding, consumer verification, and fail-closed replay/misbinding behavior.

The pass reviewed the tag-triggered release workflow, validated artifact/checksum/SBOM generation, GitHub `actions/attest` subject selection, GitHub CLI attestation verification identity controls, existing release guidance, and permanent release-integrity gates. It did not execute or import scanned target repository code, probe discovered endpoints, or collect credentials.

## Findings

1. Build-provenance and SBOM attestations independently rediscovered subjects with `subject-path: "dist/*"` after `SHA256SUMS` had already been generated from validated artifact reads. The intended artifact identities therefore were not explicitly anchored to the validated checksum manifest used by release metadata.
2. The release workflow treated successful attestation creation as sufficient and did not verify the generated bundles against the exact artifacts about to be published before creating the GitHub Release.
3. Existing consumer guidance said to verify repository/tag attestations but did not require the exact signer workflow, source ref, source commit, signer-workflow digest, hosted-runner constraint, and predicate type. Repository-only verification is weaker because a valid attestation from another workflow/ref/commit can be misbound to the release being reviewed when artifact bytes overlap.
4. The downloaded `agentcapdiff.spdx.json` asset was not explicitly compared with the signed SPDX predicate by a documented fail-closed helper.

## Fix

- Both `actions/attest` steps now identify the exact wheel/source-distribution subjects from `release/SHA256SUMS` via `subject-checksums`; release attestations no longer rediscover subjects through a `dist/*` glob.
- Added a project-specific release attestation verifier that checks exact filenames, local SHA-256 values, SPDX artifact hashes, repository identity, signer workflow, source tag, source commit, signer workflow digest, GitHub Actions OIDC issuer, hosted-runner requirement, predicate type, attested subject name/digest, and exact signed-SPDX-to-published-SBOM equality.
- The publish job self-verifies both generated attestation bundles against the current local artifacts before `gh release create` can run.
- Added a dedicated attestation-integrity static gate and regression tests so `subject-path`/`subject-digest` rediscovery or removal of the strict verification path fails CI.
- Added consumer verification guidance with exact `gh attestation verify` identity constraints and optional offline bundle verification.

## Compatibility

Package/runtime version remains `1.0.0`. Capability, policy, JSON, SARIF, snapshot, diff, benchmark, and CLI contracts are unchanged.

## Residual risk

GitHub Actions OIDC, GitHub/Sigstore trusted roots, GitHub CLI verification, the hosted runner/toolchain, and the reviewed release workflow remain external trust boundaries. Exact subject/source/signer verification prevents accidental or weaker replay/misbinding but does not prove the workflow itself is uncompromised or that the source is vulnerability-free.

A signed predicate is evidence produced by an authorized workflow; it is not independent proof that every claim inside workflow-controlled predicate content is truthful. UNKNOWN is not SAFE.
