# Audit 2026-08-28 — output-file/path write safety

Scope: one post-v1.0 audit pass covering explicit local output-file writes, atomicity, symlink/path redirection, and fail-closed behavior. This pass does not change capability/policy semantics, machine-readable report contents, snapshot schema, or package version.

## Findings

1. `scan --output` and `diff --output` used `Path.write_text()`. An existing symlink was therefore followed to its target and an existing regular report was truncated before the replacement contents were known to be complete.
2. `snapshot --output` used the same direct write pattern through `write_snapshot()`, so snapshot publication had the same link-following/partial-overwrite behavior.
3. Output-path write failures were outside the CLI's normalized invalid-input handling and could surface as an uncaught filesystem exception rather than a controlled fail-closed exit.
4. The safety benchmark's `--output` path also used a direct write and could follow a link or partially replace an existing benchmark artifact.
5. Existing output tests established that scanned metadata could not choose an output location, but did not cover symlinked destinations/parents, non-regular files, atomic replace failure, or a destination-link race at commit time.

## Fixes

- Added one shared UTF-8 atomic output writer for AgentCapDiff package output surfaces.
- Existing destination entries must be regular files; symlink and non-regular destinations fail closed.
- Parent directories must already exist and symlink/redirection through the parent path is rejected.
- POSIX parent traversal uses no-follow directory descriptors, pinning the selected parent tree rather than resolving it again during the write.
- New contents are written to an exclusive same-directory temporary file, fully written and `fsync`ed, then committed with atomic replacement.
- A replacement failure leaves the previous valid output untouched and temporary artifacts are cleaned up.
- Atomic replacement operates on the destination directory entry and does not follow a destination symlink even if a link is introduced after the pre-commit check.
- `scan`, `diff`, and `snapshot` normalize rejected output paths to exit code `3` with a concise stderr message; the benchmark returns its ordinary non-zero gate result without a traceback.

## Regression coverage

Permanent tests cover:

- scan output symlink rejection with target preservation;
- snapshot output symlink rejection with target preservation;
- symlinked parent rejection;
- non-regular destination rejection;
- failed atomic replacement preserving the previous complete output;
- cleanup of temporary files after a failed commit;
- a symlink introduced at the final replace race not being followed to its target;
- benchmark output using the same fail-closed writer;
- successful atomic replacement still producing valid machine-readable JSON.

## Compatibility and boundaries

The explicit `--output` option remains operator authority and valid regular-file destinations preserve their content contract. Parent directories remain caller-created, matching the previous behavior of the main CLI. Existing regular files are still replaceable, but publication now happens atomically rather than through in-place truncation.

The internal release SBOM path is generated inside a workflow-owned `release/` directory and is not selected by scanned metadata; redesigning release asset creation is outside this scanner-originated output pass. Shell redirection such as `sha256sum ... > release/SHA256SUMS` is also controlled by the release workflow rather than AgentCapDiff's Python output API.

Atomic/no-follow writes reduce path-redirection and partial-publication risk; they do not protect against an adversary that already has the same operating-system authority to mutate the destination directory after AgentCapDiff returns. Filesystem permissions and process isolation remain separate controls.
