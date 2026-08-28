# Audit 2026-08-28 — package artifact hashes and CI provenance

## Scope

Exactly one AUDIT pass covering Python package artifact hash pinning, pip bootstrap provenance, GitHub-hosted runner image provenance, exact Python selection, and fail-closed CI/release supply-chain inputs.

The pass reviewed the complete CI/release dependency lock, all seven workflows, setup-python use, the current GitHub Ubuntu 24.04 runner image, completed CI logs, and the release-integrity enforcement path. It did not execute or import scanned target repository code, probe discovered endpoints, or collect credentials.

## Findings

1. Exact dependency versions did not bind the bytes downloaded from the package index.
2. CI/release dependency installation did not require hashes, so a same-version replacement or index-side artifact change was outside the repository's evidence boundary.
3. setup-python inputs used minor-only `3.11`, `3.12`, and `3.13`, allowing patch-version drift between otherwise identical source runs.
4. Workflows used the moving `ubuntu-latest` runner alias and did not compare the observed hosted-image version against a reviewed value.
5. The ambient Python/pip used by jobs without setup-python was not explicitly verified.
6. The pip bootstrap supplied by setup-python was not version-allowlisted.
7. GitHub-hosted runners cannot currently be selected by immutable VM-image digest through `runs-on`; Python/pip executable bytes remain external hosted-toolchain trust inputs even after version allowlisting.

## Fix

- Converted `requirements/ci-lock.txt` into a wheel-only SHA-256 lock. Each exact dependency pin now carries reviewed artifact hashes; compiled packages include only the Linux x86-64 wheels needed by supported CPython 3.11–3.13.
- Dependency installation now uses pip isolated mode with `--require-hashes`, `--no-deps`, `--no-cache-dir`, `--only-binary=:all:`, an explicit `https://pypi.org/simple` index, and a disabled pip version check. A mismatched artifact fails before installation.
- Pinned setup-python requests to exact patches `3.11.16`, `3.12.14`, and `3.13.15`.
- Replaced `ubuntu-latest` with `ubuntu-24.04` in every workflow.
- Added `requirements/ci-environment.json` and `scripts/check_ci_environment.py` to record and verify the reviewed runner family, Linux/x64 identity, Ubuntu version, GitHub image identity/version, exact Python version, and pip version.
- CI evidence established setup-python pip `26.2.1` for all three reviewed Python patches; that version is now explicitly fail-closed allowlisted. Ambient jobs separately verify Python `3.12.3` and pip `24.0`.
- Added the provenance probe to every workflow job before build/test/security work.
- Extended the permanent release-integrity gate and regression tests to reject unhashed locks, unapproved lock install commands, moving runner aliases, minor-only Python pins, missing runner/Python/pip provenance checks, image-version drift, and pip-version drift.

## Compatibility

Package/runtime version remains `1.0.0`. Capability, policy, JSON, SARIF, snapshot, diff, benchmark, and CLI contracts are unchanged.

## Residual risk

GitHub-hosted `ubuntu-24.04` selects a runner family rather than an immutable VM image digest. The observed image version is therefore checked after scheduling and the job fails closed if it differs from the reviewed value; this is an allowlist, not cryptographic VM-image pinning.

The setup-python Action is commit-SHA pinned, exact Python patches are requested, and pip `26.2.1` is version-allowlisted, but the Python/pip executable bytes supplied by the hosted toolcache are not cryptographically pinned by this repository. Dependency SHA-256 verification depends on that local verifier behaving correctly. PyPI remains an external availability/metadata dependency; the explicit simple-index URL is reviewable, and package bytes not matching a reviewed hash cannot pass the install gate.

UNKNOWN is not SAFE.
