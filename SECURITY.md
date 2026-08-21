# Security Policy

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that could enable exploitation of users. Use GitHub private vulnerability reporting when enabled for the repository. If private reporting is unavailable, contact the maintainer through the email associated with the GitHub profile and include `AgentCapDiff security` in the subject.

## Scope

Security issues include, but are not limited to:

- crafted tool definitions causing unintended command execution
- path traversal or unsafe file writes performed by AgentCapDiff itself
- SARIF/output injection that creates a meaningful security boundary bypass
- policy parser behavior that silently weakens explicit deny rules

Classifier false positives/negatives are normally correctness issues unless they create a concrete security boundary bypass.
