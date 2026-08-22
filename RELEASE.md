# Release verification

A release is complete only after its roadmap items, release gate, version metadata, documentation, issue states, and required GitHub checks agree on `main`.

For v0.2.0 the release PR must close #5, #6, #8, and #10, keep #15 completed, pass CI on Python 3.11–3.13, CodeQL, AgentCapDiff self-policy, PR capability diff, and project-state consistency, then be merged and read back from `main`.
