# Release verification

A release is complete only after its roadmap items, release gate, version metadata, documentation, issue states, and required GitHub checks agree on `main`.

## v0.9 release checklist

Before creating a production tag:

- package version and runtime `__version__` are identical and finalized (no `.dev0`);
- the tag is exactly `v<package-version>`;
- ROADMAP marks the release section complete and README/CHANGELOG agree;
- CI passes on Python 3.11, 3.12, and 3.13;
- CodeQL passes;
- AgentCapDiff self-policy passes;
- PR capability diff and project-state consistency pass;
- the reproducible safety benchmark has zero high-risk false-negative regression and zero parser failure relative to its committed gate;
- release-integrity workflow passes Action/dependency pin checks, build smoke test, and SPDX SBOM validation;
- parser/path/output/CI trust-boundary security regressions are green;
- issue #14 acceptance criteria are complete.

Repository administrators must enable GitHub release immutability before pushing a production release tag. The release workflow treats this as external security state and verifies GitHub reports `isImmutable=true` after publication. If it does not, the workflow fails closed and attempts to delete the mutable release/tag.

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

A reviewed immutable release tag may also be used where that release and its attestations have been verified. Do not rely on `@main` for production. Never move or reuse a released version tag.

See `docs/release-integrity.md` for artifact verification, immutable-release requirements, and compromise/revocation procedures.
