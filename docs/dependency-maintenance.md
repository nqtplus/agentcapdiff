# Dependency maintenance and update trust policy

AgentCapDiff treats dependency updates as supply-chain changes, not as routine text edits. A Dependabot identity, green badge, or newer version is not by itself evidence that an update is safe.

## Current automation policy

### Python packages

`requirements/ci-lock.txt` is a reviewed, wheel-only, SHA-256-pinned closure used by CI and release workflows. Direct package versions are also represented across `pyproject.toml` and `requirements/ci-direct.txt`.

Because this is a multi-manifest/custom-lock design, routine Python **version-update** pull requests from Dependabot are disabled with `open-pull-requests-limit: 0`. GitHub documents that this disables version-update PRs while Dependabot security updates remain separate.

Python security updates may still be proposed automatically. They are never auto-merged and must satisfy the same required repository checks as every other pull request.

A routine Python freshness update is therefore a coordinated maintainer change:

1. choose the reviewed direct version(s);
2. update every matching exact pin in `pyproject.toml` and `requirements/ci-direct.txt`;
3. resolve the complete supported CI closure deliberately;
4. replace `requirements/ci-lock.txt` with exact versions and SHA-256 hashes only for accepted wheel artifacts;
5. keep the public PyPI simple index and the existing `--require-hashes --no-deps --only-binary=:all:` install contract;
6. run the full Python 3.11/3.12/3.13 CI matrix, `pip check`, release-integrity gates, CodeQL, and the safety benchmark;
7. review the final PR head after all updates/rebases before merge.

If an automated security PR cannot update all duplicated pins and hashes coherently, the correct response is to make a coordinated reviewed PR. Do not weaken hash checking, exact pins, `pip check`, or required status checks to make the bot PR pass.

## GitHub Actions

Dependabot version updates remain enabled weekly for the currently reviewed Action suppliers only:

- `actions/checkout`
- `actions/setup-python`
- `actions/attest`
- `github/codeql-action`

The repository independently requires every non-local Action reference to use a full 40-character commit SHA and rejects any Action supplier outside the code-owned allowlist. The Dependabot allowlist is defense in depth, not the root of trust.

Routine Action version updates use a seven-day cooldown. Security-relevant evidence can justify an earlier manual update; cooldown must never be used as a reason to postpone a known required security fix.

## Dependabot pull-request boundary

A Dependabot PR is restricted to the surfaces the bot is expected to maintain:

- `pyproject.toml`
- `requirements/ci-direct.txt`
- `requirements/ci-lock.txt`
- files directly under `.github/workflows/` ending in `.yml` or `.yaml`

A Dependabot PR touching source code, scripts, policies, repository settings/configuration, CI provenance data, docs, or any other path fails closed.

For Python updates, the exact direct-pin set and versions must stay synchronized between project metadata and the CI direct manifest. The existing release-integrity gate separately requires the direct pins to exist at the same versions in the SHA-256-pinned full lock.

For GitHub Actions updates, a full SHA is necessary but not sufficient: the Action repository must also remain in the reviewed supplier allowlist.

## Merge policy

- Repository auto-merge is intentionally disabled.
- No dependency bot is a bypass actor for the protected default branch.
- Required checks must be green for the **latest** PR head.
- A bot-authored PR is reviewed by its content and resulting dependency graph/action identity, not trusted because of author metadata alone.
- Any unexpected file, registry, target branch, Action supplier, conditional dependency, URL/VCS dependency, source distribution, or mutable dependency reference is `UNKNOWN`, not safe.

## Freshness cadence

- Dependabot security updates: event-driven by GitHub/Dependabot.
- GitHub Actions routine version checks: weekly, with a seven-day version-update cooldown.
- Python routine direct-version review: at least monthly, or sooner when a supported Python/runtime change, security advisory, or important upstream fix requires it.
- Runner image, Python patch, and pip bootstrap provenance remain governed separately by `requirements/ci-environment.json` and the CI provenance gate.

The goal is not “latest at all costs.” The goal is a reviewed, reproducible dependency state with bounded automation and explicit provenance.
