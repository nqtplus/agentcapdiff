# Audit 2026-08-28 — CI/release dependency reproducibility

## Scope

Exactly one AUDIT pass covering Python dependency resolution, pip cache state, transitive dependency provenance, and fail-closed reproducibility for AgentCapDiff CI/release workflows.

The audit reviewed the Python 3.11–3.13 CI/release installation paths, `requirements/ci-direct.txt`, setup-python cache configuration, Dependabot coverage, release-integrity enforcement, and a completed main-branch release-integrity log. It did not execute/import scanned target repository code, probe discovered endpoints, or collect credentials.

## Finding

The repository exactly pinned six direct CI/release dependencies, but pip still resolved their transitive closure dynamically. A completed release-integrity run showed packages such as `packaging`, `pyproject_hooks`, `pathspec`, `pluggy`, `tomlkit`, `trove-classifiers`, `iniconfig`, `Pygments`, and `coverage` being selected from version ranges at install time.

setup-python's pip cache key was derived from the direct requirements file. Therefore an unchanged source commit/direct-pin file did not fully identify the dependency closure or the mutable cached package state used by a later run.

## Fix

- Added `requirements/ci-lock.txt` containing the full currently required dependency closure with exact versions.
- Kept `requirements/ci-direct.txt` as the reviewed direct-dependency declaration and require every direct pin to match the lock.
- Changed all CI/release dependency installs to use the lock with `--no-deps`, preventing hidden transitive resolution.
- Disabled setup-python pip caching for these installs and use `--no-cache-dir` to remove cross-run cache state from the dependency boundary.
- Added `--only-binary=:all:` so an unavailable wheel fails closed instead of executing an sdist build path during dependency installation.
- Added `python -m pip check` after every locked install so an incomplete or incompatible lock fails on each supported Python version.
- Extended `scripts/check_release_integrity.py` and regression tests to enforce the lock/direct relationship and workflow install contract.

## Compatibility

Package/runtime version remains `1.0.0`. Capability, policy, JSON, SARIF, snapshot, diff, benchmark, and CLI contracts are unchanged.

## Residual risk

This pass freezes versions and removes pip resolver/cache drift, but it does not yet cryptographically pin the bytes of package artifacts, the pip executable bundled by the runner, the GitHub-hosted runner image, or the external package index. Exact versions are therefore stronger and more reproducible than the prior state, but they are not a complete cryptographic software-supply-chain proof. UNKNOWN is not SAFE.
