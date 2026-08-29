# Dependency/update automation audit — 2026-08-29

## Scope

This is one coherent post-v1.0 audit pass covering:

- Dependabot trust boundaries;
- Python direct/lock manifest synchronization;
- SHA-256 lock update semantics;
- GitHub Action update provenance and supplier allowlisting;
- bot-authored PR changed-file boundaries;
- dependency freshness versus review stability;
- auto-merge and required-check assumptions.

Baseline main before the audit:

`8bb995ecbbb494fe2b7948807d88405a9d237bf5`

Package/API/output compatibility remains v1.0.0 and is not changed by this audit.

## Baseline findings

### 1. Routine Python Dependabot version PRs were enabled against a custom multi-manifest lock design

Dependabot was configured to scan the root pip ecosystem weekly with up to five version-update PRs. AgentCapDiff, however, keeps overlapping direct versions in `pyproject.toml` and `requirements/ci-direct.txt`, while CI/release installation uses a separately reviewed full SHA-256 lock in `requirements/ci-lock.txt`.

The existing integrity gate required CI direct pins to appear in the lock, but it did not require project metadata, build requirements, development requirements, and `ci-direct.txt` to remain exactly synchronized. A partial automated update could therefore create metadata/runtime/build-tool drift even if the file itself looked like a normal dependency bump.

### 2. A full Action SHA did not constrain the Action supplier

The repository already required third-party Actions to be pinned to full 40-character commit SHAs. That prevents floating-tag drift but did not prevent a pull request from replacing a reviewed Action with a different Action repository that also used a full SHA.

A full SHA answers “which commit?”; it does not answer “whose repository is trusted?”.

### 3. Dependabot identity did not bound the files a bot-authored PR could change

Required checks applied to Dependabot PRs, but there was no explicit invariant limiting a bot-authored update to dependency manifests/locks and workflow Action references. Author identity was therefore not coupled to a narrow expected change surface.

### 4. No auto-merge path was found

Repository metadata showed `allow_auto_merge=false`. Existing branch governance requires the protected PR/check path, so this audit did not find a current automatic merge/bypass route for dependency updates.

No existing Dependabot-authored PR history was present to use as empirical update evidence, so bot behavior outside the checked-in configuration remains an external input and is not assumed safe.

## Remediation

### Python automation boundary

Routine pip version-update PRs are disabled with `open-pull-requests-limit: 0`; security updates remain the automated path. Routine Python freshness updates are coordinated maintainer PRs so project metadata, CI direct pins, the complete closure, and hashes are reviewed together.

A new permanent checker requires the exact direct-pin set and versions in `pyproject.toml` to agree with `requirements/ci-direct.txt`, except for the explicitly reviewed maintenance-only `build` tool. The existing release-integrity checker continues to require those direct pins at the same versions in the SHA-256 lock.

### Action provenance boundary

The new checker allows only the currently reviewed Action repositories/sub-actions:

- `actions/checkout`
- `actions/setup-python`
- `actions/attest`
- `github/codeql-action/init`
- `github/codeql-action/analyze`
- `github/codeql-action/upload-sarif`

Every reference must still be a full commit SHA. Dependabot itself is also configured to update only the corresponding Action repositories.

Adding another Action supplier now requires an explicit security review and code-owned allowlist change instead of passing merely because a 40-character SHA is present.

### Dependabot changed-file boundary

On Dependabot pull requests, the required `Project state consistency` job runs the dependency-update checker against the exact base/head SHAs. The checker obtains NUL-delimited changed paths directly from `git diff` with a bounded output size and accepts only:

- `pyproject.toml`;
- `requirements/ci-direct.txt`;
- `requirements/ci-lock.txt`;
- direct `.github/workflows/*.yml` / `*.yaml` files.

Any other bot-touched path fails closed.

### Trusted control plane

On pull requests, the new dependency-update checker is selected from the exact trusted base worktree once that checker exists in the base revision. This audit PR necessarily bootstraps the newly introduced checker from the candidate branch because the pre-audit base does not contain it; the job is read-only and the candidate implementation is covered by normal CI tests. After this audit is merged, future PRs are base-anchored.

The checker is also wired into release-integrity, normal CI regression gates, and release validation so the dependency policy cannot silently disappear after merge.

### Freshness policy

- pip security updates stay automated;
- routine Python version refresh is reviewed at least monthly;
- GitHub Actions version checks remain weekly with a seven-day cooldown;
- known security fixes are not delayed merely to satisfy cooldown;
- no dependency update is auto-merged.

Detailed maintenance procedure: `docs/dependency-maintenance.md`.

## Residual trust boundaries

- GitHub Dependabot service behavior and security-advisory coverage remain external trust inputs.
- PyPI account/project security and the authenticity of artifacts associated with an accepted hash remain external trust inputs.
- GitHub Action repository ownership and upstream account security remain external trust inputs even when an exact commit is pinned.
- A human maintainer still decides whether a new dependency/version/supplier should enter the allowlisted trust set.
- The custom Python lock is deliberately review-driven rather than automatically regenerated; this reduces unreviewed drift but does not guarantee that the chosen versions are defect-free.

`UNKNOWN` is not treated as safe.
