# Audit — release auxiliary artifact integrity (2026-08-28)

## Scope

One AUDIT pass covering the tag-release boundary for built artifact selection, SPDX/SHA256 auxiliary metadata generation, path containment, symlink handling, and fail-closed publication behavior.

This pass does not change AgentCapDiff capability semantics, scanner behavior, JSON/SARIF/snapshot contracts, or package version `1.0.0`.

## Findings

The existing release workflow had three related defense-in-depth gaps:

1. `dist/` and `release/` were not explicitly reset immediately before the privileged publish build, so a stale/tracked entry or symlink could theoretically join or redirect the release set.
2. `scripts/generate_sbom.py` selected `dist_dir.iterdir()` entries with `is_file()` and wrote its output with `Path.write_text()`, both of which could follow symlinks. It also accepted extra files without requiring the exact versioned wheel/sdist set.
3. `sha256sum dist/*` and `gh release create ... dist/* release/*` used broad globs rather than binding checksums/publication to the exact validated artifacts.

These findings concern release artifact integrity; they are not evidence that an existing published release was compromised.

## Fixes

- release jobs remove and recreate `dist/` and `release/` before building;
- `python -m build` writes explicitly to the fresh `dist/` directory;
- the SBOM generator requires exactly the current-version wheel and source distribution;
- symlinked, non-regular, missing, extra, or redirected artifact/output paths fail closed;
- artifact hashes are read through non-following regular-file descriptors where supported;
- `SHA256SUMS` is derived from the exact same hashes recorded in the SPDX document;
- SBOM/checksum destinations are prevalidated and written via same-directory temporary files plus atomic replacement;
- release publication names the exact versioned wheel, source distribution, SPDX file, and checksum file;
- the release-integrity checker permanently rejects regression to broad checksum/publication patterns;
- regressions cover reproducibility, unexpected artifacts, symlink artifacts, symlink output targets/parents, and prevalidation of both auxiliary outputs.

## Residual risk

The release workflow still relies on GitHub-hosted runners, pinned external Actions, pinned Python dependencies, repository release-immutability state, and the correctness of the reviewed source/build toolchain. Artifact validation reduces path confusion and unintended publication; it does not prove source-code correctness or eliminate the need to verify hashes and attestations.

No target repository code is scanned or executed by this release path, and no discovered endpoint or scanned credential is used.
