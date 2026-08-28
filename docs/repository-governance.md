# Repository governance and server-side enforcement

AgentCapDiff treats GitHub repository settings as a separate security boundary from source-controlled CI. A workflow file can express the intended checks, but it cannot by itself stop an administrator or direct push from updating an unprotected branch or tag.

## Required production governance

For the public `nqtplus/agentcapdiff` repository, use active GitHub rulesets (or equivalent branch/tag protection with the same effect) for both the default branch and release tags.

### Default branch: `main`

Target the default branch (`~DEFAULT_BRANCH` / `refs/heads/main`) and require all of the following:

- changes enter through a pull request rather than direct push;
- required status checks are strict/up-to-date before merge;
- branch deletion is blocked;
- non-fast-forward/force-push updates are blocked;
- linear history is required;
- bypass actors are empty unless an emergency exception is explicitly reviewed and documented.

The required status-check contexts must include the current PR gates:

- `test (3.11.16)`
- `test (3.12.14)`
- `test (3.13.15)`
- `analyze`
- `capability-policy`
- `capability-diff`
- `state`
- `integrity`

These are job/check names, not workflow display names. If a workflow job is renamed, the ruleset must be updated in the same reviewed change or the repository can become either under-enforced or permanently blocked.

For this single-maintainer repository, requiring a pull request with zero mandatory external approvals is acceptable if independent review is unavailable; the non-negotiable controls are PR-only updates plus the required checks. If additional trusted maintainers are added, require at least one approval and stale-review dismissal.

### Production release tags

Target `refs/tags/v*.*.*` and require:

- existing matching tags cannot be updated/moved;
- existing matching tags cannot be deleted through normal repository operations;
- bypass actors are empty unless an emergency exception is explicitly reviewed and documented.

Do not restrict creation of new version tags unless the release process is deliberately changed to use a reviewed bypass path. The release workflow needs a newly created version tag as its trigger.

GitHub immutable releases remain a separate control. After publication, immutable-release protection additionally binds the release assets and associated tag. The release workflow already fails closed if GitHub does not report release immutability before accepting a production publication.

## Verification after configuration

After changing repository settings, verify all of these from fresh GitHub state rather than relying on screenshots or remembered settings:

1. `GET /repos/nqtplus/agentcapdiff/branches/main` reports `protected: true`.
2. `GET /repos/nqtplus/agentcapdiff/rulesets` returns the active branch/tag rulesets.
3. The branch ruleset targets the default branch and contains PR-only, strict required-status-check, deletion, non-fast-forward, and linear-history rules.
4. The required status-check list contains every current PR gate listed above.
5. The tag ruleset targets `refs/tags/v*.*.*` and blocks update/deletion.
6. No undocumented bypass actor is present.
7. A test PR cannot merge until every required check succeeds.
8. A direct update/force-push attempt to `main` is rejected by GitHub server-side enforcement.
9. A moved/deleted existing production-style tag is rejected by the tag ruleset.
10. Production release publication still requires GitHub immutable-release enforcement.

Do not perform destructive tests against a real production tag. Use a temporary non-production branch and, if tag-rule behavior must be exercised, a disposable test tag outside the production namespace or a specifically planned test repository.

## Drift rule

Source-controlled CI success is not proof that repository governance is active. If branch protection/rulesets cannot be freshly verified, governance status is `UNKNOWN`, not `SAFE`.

Any change to workflow job names, merge strategy, release-tag pattern, repository ownership, bypass actors, or GitHub plan/features should trigger a fresh governance review.

## Current tooling boundary

The ChatGPT GitHub connector used by the maintenance process can read repository rulesets and high-level branch protection state but does not expose a write action for branch protection/rulesets. Therefore server-side governance changes must be applied through GitHub Settings or another explicitly authorized administration client, then verified from fresh API state before this control is marked complete.
