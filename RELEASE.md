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

The tag-triggered release workflow re-runs validation and CodeQL before publication. A production release is accepted only when GitHub reports `isImmutable=true`; otherwise the workflow fails closed and attempts to delete the mutable release/tag.

The merge of v1.0 source state and the publication of an immutable GitHub Release are separate events: source state may be marked stable only after the PR release gate passes, while a production release asset/tag is trusted only after the tag workflow and immutable-release verification pass.

## Release workflow output

A successful tag-triggered release creates:

- wheel and source distribution;
- `SHA256SUMS` for built artifacts;
- `agentcapdiff.spdx.json` SPDX 2.3 SBOM;
- GitHub build provenance attestation for release artifacts;
- GitHub SBOM attestation bound to those artifacts;
- an immutable GitHub Release.

The workflow starts with `permissions: {}` and grants only per-job permissions. Validation and CodeQL must finish successfully before the publish job receives write/attestation permissions.

## Production pinning

For the composite GitHub Action, a reviewed full commit SHA is the strongest source-level production pin:

```yaml
- uses: nqtplus/agentcapdiff@<reviewed-full-commit-sha>
```

A reviewed verified immutable release tag may also be used where that release, checksums, SBOM, and attestations have been verified. Do not rely on `@main` for production. Never move or reuse a released version tag.

## Historical v0.9 release gate

v0.9 established the supply-chain baseline carried into 1.x: exact Action/dependency pins, benchmark/release-integrity gates, SPDX SBOM, checksums, attestations, least-privilege workflow permissions, immutable release enforcement, and parser/path/output/CI trust-boundary review.

See `docs/stability-v1.0.md` for 1.x compatibility guarantees, `docs/v1.0-verification.md` for the stable-release evidence map, and `docs/release-integrity.md` for artifact verification, immutable-release requirements, and compromise/revocation procedures.
