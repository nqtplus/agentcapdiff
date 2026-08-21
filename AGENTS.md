# AGENTS.md

## Project goal
Keep AI-agent capabilities reviewable, explainable, and enforceable in CI.

## Engineering rules
- Do not execute target repository code during static discovery.
- Keep capability inference explainable and covered by fixtures/tests.
- Treat policy weakening as security-sensitive.
- Prefer small framework adapters over framework-specific policy engines.
- New rules require at least one positive and one negative test fixture.
- Preserve CLI exit-code behavior and machine-readable output compatibility.
