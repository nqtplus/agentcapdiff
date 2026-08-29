# GitHub Actions trust-boundary audit — 2026-08-29

## Scope

This is one coherent post-v1.0 audit pass covering:

- GitHub Actions event and permission attack surface across all workflows;
- pull-request and fork trust boundaries;
- execution of pull-request-controlled repository code;
- mutable workflow file-command channels such as `GITHUB_ENV`, `GITHUB_PATH`, and `GITHUB_OUTPUT`;
- cache/artifact handoff and event-chaining side channels;
- release-job privilege separation.

The standing AgentCapDiff safety invariant remains unchanged: static analysis must never execute or import the repository being scanned.

## Baseline

Verified main before the audit:

`6c226b735c4159cef3c54eb34976e80d82cf306f`

Repository governance was already active: `main` was protected by `protect-main`, production-style tags were protected by `protect-release-tags`, and release immutability was enabled.

## Findings

### 1. Static PR workflows executed pull-request-controlled code

`Agent capability policy` and `PR capability diff` installed the package from the pull-request checkout before performing static analysis. A pull request can change Python package/build metadata and scanner implementation, so the code performing the scan was not anchored to a trusted base revision.

This contradicted the explicit static-analysis invariant even though the jobs used GitHub-hosted runners and did not persist checkout credentials.

### 2. Write-capable CodeQL/SARIF jobs invoked a checker from the PR checkout

The CodeQL and SARIF paths held `security-events: write` while a repository-local provenance checker was read from the pull-request checkout. A changed checker could affect later process state, including environment or executable-path behavior, before the privileged security upload/action steps.

### 3. Integrity gates used candidate copies of their own checker scripts

Project-state and release-integrity jobs evaluated candidate repository state by executing checker scripts from that same candidate checkout. This created a self-reference: a pull request changing a protected invariant could also change the code that judged that invariant.

### 4. No current privilege-chaining/cache/artifact injection was found

The audit found no `pull_request_target`, `workflow_run`, Actions cache, artifact upload/download handoff, or direct interpolation of PR title/body/head-ref metadata into shell commands. The release workflow remained tag-only, started from `permissions: {}`, and retained write/id-token privileges only in its publish job.

## Remediation

### Trusted-base static analysis

The two static PR workflows now:

1. check out the candidate tree with credentials non-persistent;
2. materialize the exact `github.event.pull_request.base.sha` as a detached sibling worktree;
3. verify runner provenance from that base worktree;
4. install the hash-locked dependencies and AgentCapDiff package from that base worktree only;
5. treat the pull-request tree solely as untrusted static input.

The PR capability summary still compares base and head data, but both snapshots are produced by the trusted-base scanner.

### Trusted control plane for security/integrity jobs

On pull requests:

- CodeQL runs the environment-provenance checker from the exact base commit;
- project-state runs the release-integrity checker from the exact base commit against the candidate root;
- release-integrity runs its release, attestation, and transaction checker implementations from the exact base commit against the candidate root.

On trusted `main` push/schedule events, the current checked-in control plane is used.

### Permanent regression gate

`scripts/check_actions_trust_boundaries.py` now fails closed if reviewed trust-boundary properties drift. It checks, among other things:

- no `pull_request_target` or `workflow_run` privilege bridge;
- no Actions cache or artifact handoff in the current workflow design;
- no direct PR title/body/head-ref command injection surface;
- no mutable `GITHUB_ENV`/`GITHUB_PATH`/`GITHUB_OUTPUT` channel in write-capable PR workflows;
- static PR scanners install exactly one package source and that source is the trusted base worktree;
- CI that deliberately executes candidate code remains read-only and does not receive secret/file-command channels;
- project/release integrity gates select trusted-base checkers for pull requests;
- the release workflow remains unreachable from `pull_request` and retains an empty top-level permission set.

Negative regression tests cover the new gate.

## Intentional residual boundary

The normal CI matrix deliberately executes and tests candidate AgentCapDiff code. It therefore is **not** treated as a sandbox or proof that hostile contributor code is safe. Its token remains read-only, checkout credentials are not persisted, and this audit does not introduce secrets, caches, artifact handoff, or privileged follow-up jobs into that execution path.

GitHub-hosted runner implementation, GitHub token semantics, repository settings, and the GitHub control plane remain external trust roots. Future changes to workflow events, permissions, caches/artifacts, or server-side governance must be freshly audited; UNKNOWN is not SAFE.
