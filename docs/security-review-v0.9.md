# v0.9 security-focused trust-boundary review

This review covers the scanner-originated trust boundaries named in the v0.9 roadmap: parser, path traversal, output rendering, and CI/release execution. It is a source-backed review of AgentCapDiff itself, not a claim that scanned agents are safe.

## Scope and reviewed controls

### Parser and resource boundary

Reviewed `src/agentcapdiff/discovery.py` and the parser/fuzz regression suites.

Controls retained or verified:

- JSON parsing and `yaml.safe_load` only; no arbitrary YAML object construction;
- per-file byte, aggregate byte, candidate-document, nesting-depth, and structured-node limits;
- iterative/cycle-aware object traversal so YAML aliases do not recurse forever;
- malformed/unreadable documents do not crash traversal; resource-limit violations remain fail-closed;
- framework discovery uses serialized metadata only and never imports target SDKs or target repository code.

Residual risk: bounded structured parsing can still consume CPU/memory within configured limits, and unsupported/generated behavior can remain unclassified. The safety benchmark and unknown reporting are intended to make classifier limitations visible rather than turn them into a safety guarantee.

### Filesystem/path boundary

Reviewed scan-root discovery, inherited-policy loading, explicit output writes, and symlink tests.

Controls retained or verified:

- symlinked files are rejected before reading;
- v0.9 additionally rejects a symlinked directory supplied as the scan root;
- candidate file resolution is checked against the resolved scan-root boundary before parsing;
- policy inheritance rejects absolute/escaping paths, cycles, excessive depth, and symlinked policy files;
- scanner output is written only to explicit CLI output paths and is never selected by scanned metadata.

The symlinked-directory root case was an uncovered path boundary during this review and is now a permanent regression test.

Residual risk: the user invoking the CLI can intentionally choose an arbitrary local scan/output path. That is operator authority, not authority derived from untrusted scanned input.

### Reviewer-output boundary

Reviewed Markdown/SARIF/JSON reporting and existing output-injection regressions.

Controls retained or verified:

- Markdown escapes HTML-sensitive and Markdown-control characters and normalizes embedded line breaks before rendering untrusted values;
- JSON and SARIF are serialized structurally rather than assembled as raw JSON text;
- capability/scope/path explanations keep severity, confidence, evidence, and unknown state distinct;
- output tests cover attempts to inject HTML/Markdown through untrusted scope values.

Residual risk: downstream renderers and code-scanning platforms remain separate trust boundaries. Structured escaping prevents known review-format injection classes but does not make arbitrary downstream consumers correct.

### Pull-request CI boundary

Reviewed all `.github/workflows` and the composite Action.

Controls introduced or verified in v0.9:

- every third-party GitHub Action is pinned to a full commit SHA;
- `pull_request_target` is forbidden by the release-integrity gate;
- `write-all` is forbidden;
- normal PR jobs use read-only contents unless a narrowly scoped security upload requires `security-events: write`;
- SARIF upload is conditioned so an untrusted fork PR is not treated as a privileged publication path;
- the PR capability diff uses a detached base worktree and static scanner operations only; it does not execute base/head target code;
- direct CI/release dependencies are reviewed exact pins and Dependabot updates Python and Action references through PR review.

Residual risk: any GitHub-hosted Action or package can later be found compromised at the already-pinned commit/version. Pinning prevents silent ref movement; it does not eliminate the need for revocation/advisory response.

### Release boundary

Reviewed the new tag-triggered release workflow and integrity verifier.

Controls introduced in v0.9:

- workflow-level `permissions: {}` with job-local least privilege;
- validation and CodeQL must succeed before publication;
- release tag must exactly match finalized package/runtime version;
- wheel/source artifacts receive SHA-256 checksums, SPDX 2.3 SBOM, build provenance attestation, and SBOM attestation;
- release starts as draft and is accepted only if GitHub reports `isImmutable=true` after publication;
- if immutable-release protection is not active, the workflow fails closed and attempts to remove the mutable release/tag;
- production documentation prefers a reviewed full commit SHA or verified immutable release instead of `@main`.

Repository release immutability is GitHub-controlled external state and must be enabled by a repository administrator. The workflow intentionally treats absence of that setting as a release failure rather than silently downgrading trust.

## Review conclusion

No unresolved critical/high scanner-originated vulnerability was identified in the reviewed parser, path, output, PR-CI, or release boundaries. The review did identify and fix one defense-in-depth gap: a symlinked directory used directly as the scan root was not explicitly rejected before traversal.

The remaining risks are documented limitations rather than evidence of runtime safety. AgentCapDiff remains a static review aid: it does not execute target code, use credentials from scanned content, probe discovered endpoints, or prove that an agent is safe to run.
