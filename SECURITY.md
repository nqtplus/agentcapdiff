# Security Policy

## Supported versions

AgentCapDiff is currently **early alpha**. Until a stable release line exists, security fixes are applied to the current default branch and the most recent tagged release when practical. Older commits and floating development snapshots should not be assumed to receive backports.

For production CI, prefer a reviewed full commit SHA or a verified immutable release tag rather than a floating `@main` reference.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that could enable exploitation of users. Use GitHub private vulnerability reporting when enabled for the repository. If private reporting is unavailable, contact the maintainer through the email associated with the GitHub profile and include `AgentCapDiff security` in the subject.

A useful report includes the affected version/commit, impact, minimal reproduction, and whether the issue requires crafted repository input.

## Scope

Security issues include, but are not limited to:

- crafted tool definitions causing unintended command execution
- path traversal, symlink escape, or unsafe file writes performed by AgentCapDiff itself
- parser/resource-exhaustion behavior that can bypass or misrepresent a scan result
- SARIF/Markdown/output injection that creates a meaningful security boundary or review-integrity bypass
- policy parser behavior that silently weakens explicit deny rules
- release, dependency, or GitHub Actions behavior that introduces a meaningful supply-chain compromise path

Classifier false positives/negatives are normally correctness issues unless they create a concrete security boundary bypass or materially false assurance.

## Safety guarantees and limits

AgentCapDiff is designed for static analysis. It must not execute/import target repository code, invoke discovered tools, probe discovered endpoints, or collect credentials. Supported structured inputs are treated as untrusted and are subject to bounded parsing/traversal.

These controls reduce scanner-originated risk; they do not make the scanned agent safe to run. See [docs/threat-model.md](docs/threat-model.md) for trust boundaries, residual risks, and expected defense in depth.

## Release and supply-chain compromise

Production releases are expected to be immutable and to include checksums, an SPDX SBOM, and GitHub artifact attestations. All repository workflow Actions are pinned to reviewed full commit SHAs; direct CI/release dependencies are exact-pinned and updated through reviewed Dependabot PRs.

If a maintainer account, workflow credential, dependency, pinned Action, release artifact, tag, or attestation is suspected to be compromised:

1. stop recommending the affected release/commit immediately;
2. rotate or revoke affected credentials and disable the compromised publication path;
3. use a private security advisory while disclosure could create additional risk;
4. identify affected tags, commits, artifact SHA-256 values, and attestations;
5. do not silently replace release assets or move/reuse the affected tag;
6. publish a fixed version under a new tag only after the complete release gate passes;
7. direct users to a known-good reviewed full commit SHA or newer verified immutable release.

A release that GitHub does not report as immutable is not a trusted production release. The v0.9 release workflow fails closed and attempts to remove the mutable release/tag rather than accepting a weaker trust state.

See [docs/release-integrity.md](docs/release-integrity.md) for the complete release trust model and verification guidance, and [docs/security-review-v0.9.md](docs/security-review-v0.9.md) for the parser/path/output/CI review performed for v0.9.
