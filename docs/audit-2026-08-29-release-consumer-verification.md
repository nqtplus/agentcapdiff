# Release consumer verification audit — 2026-08-29

## Scope

This is one coherent post-v1.0 audit pass covering the consumer side of AgentCapDiff release trust:

- immutable release/tag verification after publication;
- exact reviewed source-SHA binding;
- checksum/SBOM/attestation consumption semantics;
- package installation provenance after artifact verification;
- fail-closed behavior when release, tag, dependency, or provenance evidence is unavailable.

Baseline main before this audit:

`e4c86c54f1de1682e8a1faa28608eb7932c64bc4`

The product remains v1.0.0. This audit does not change capability/policy semantics, scanner behavior, JSON/SARIF contracts, or the public package version.

## Baseline observations

At audit start, the repository had no published GitHub Releases. This is not itself a release-integrity failure: source v1.0.0 state and publication of a production GitHub Release are separate events. The audit therefore evaluates and hardens the controls that a future release consumer must use; it does not claim that a production release was verified during this pass.

The producer pipeline already had strong controls: exact version/tag checks, source-on-main validation, SHA-256 checksums, SPDX SBOM, strict provenance/SBOM attestations, least-privilege publication, exact-source retry ownership, and fail-closed immutable-release enforcement.

## Finding 1 — strict artifact attestation verification did not independently verify current release/tag state

`scripts/verify_release_attestations.py` already verified artifact hashes, SBOM binding, repository identity, signer workflow, exact source ref/digest, signer digest, OIDC issuer, hosted-runner class, and predicate type. A consumer could therefore establish strong provenance for local bytes.

However, the consumer verifier did not itself establish that the currently observed GitHub Release was published and immutable, that its asset set was the expected one, or that the current release tag still resolved to the independently reviewed source SHA. Those are separate remote-state assertions. Treating successful attestation verification as a substitute for them would collapse distinct trust boundaries.

### Remediation

The verifier now supports `--require-published-release`. In that mode it fails closed unless GitHub reports all of the following before artifact verification proceeds:

- exact requested tag;
- non-draft, non-prerelease release state;
- `isImmutable=true`;
- AgentCapDiff's exact-source ownership marker for the reviewed source SHA;
- exactly the expected wheel, source distribution, `SHA256SUMS`, and SPDX SBOM assets;
- the current tag resolves to the reviewed 40-character source SHA;
- the reviewed source remains on current `main` history.

The exact source SHA remains an independent consumer trust input rather than being learned solely from release-controlled metadata.

Producer-side prepublication self-verification intentionally does not use this flag because the Release does not exist yet. A permanent integrity gate rejects introducing that circular precondition into the producer workflow.

## Finding 2 — verified artifact bytes could be followed by unverified dependency resolution

A consumer can verify an AgentCapDiff wheel perfectly and then weaken the installation trust boundary by running an ordinary dependency-resolving `pip install`. That allows installation to select additional package bytes at a later point under a different trust decision.

### Remediation

Production guidance now separates verification from installation:

1. verify release/tag state, local package bytes, checksums, SBOM, and strict attestations;
2. install runtime dependencies from an independently reviewed exact hash lock appropriate for the interpreter/platform;
3. install the verified AgentCapDiff wheel with `--no-deps`;
4. run `pip check`.

For the reviewed Linux X64 / CPython 3.11–3.13 Action runtime, `requirements/action-runtime-lock.txt` is the repository-maintained runtime lock and is already bound to project dependencies and reviewed CI hashes. Other environments require an equivalent reviewed dependency-provenance set; unavailable provenance is `UNKNOWN`, not a reason to weaken hash verification.

Floating VCS installs, `@main`, unverified tags, and package-index name/version resolution are explicitly evaluation/development paths unless the consumer independently establishes equivalent immutable source/artifact/dependency evidence.

## Permanent regression coverage

This audit adds permanent tests/gates for:

- accepting only an exact immutable published-release binding;
- rejecting mutable release state;
- rejecting a tag that resolves to a different source SHA;
- rejecting extra/missing published assets;
- rejecting a reviewed release source that is no longer on current main history;
- preserving producer prepublication verification without an impossible published-release dependency;
- requiring consumer guidance to preserve strict attestation identity, published-release verification, hash-locked dependency installation, `--no-deps`, and `pip check`.

## Residual trust boundaries

Consumer verification still depends on the integrity and availability of GitHub release/tag APIs, GitHub CLI, GitHub/Sigstore trust roots, DNS/TLS/network paths, and the independently reviewed source SHA/workflow. Hash and attestation verification proves identity/provenance relationships for observed bytes; it does not prove absence of vulnerabilities.

An online verification is a statement about observed remote state at that time. Offline verification therefore requires separately retained/reviewed release/tag-state evidence if the consumer wants to make the same high-assurance release claim later.

`UNKNOWN` is not treated as safe.
