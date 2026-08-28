# Audit 2026-08-29 — repository governance, protected refs, and required-check enforcement

## Scope

Exactly one AUDIT pass covering GitHub repository governance/rulesets, protection of `main`, production release-tag authorization, required-check enforcement, and external-state drift.

This pass reviewed AgentCapDiff's own GitHub control plane. It did not execute/import scanned target repository code, probe discovered endpoints, collect credentials, or expand workflow permissions.

## Fresh evidence

Baseline source state was `bab65483293b18e8146f1c5a55697da52c47e749`, with v1.0/1.0.0 stable, no open issues or pull requests, and the prior post-merge push workflows green.

Fresh GitHub reads showed:

- `GET /repos/nqtplus/agentcapdiff/branches/main` returned `protected: false` and no enforced required-status-check context at branch level.
- `GET /repos/nqtplus/agentcapdiff/rulesets` returned an empty list.
- The linked GitHub account has repository admin permission, but the connected action surface does not provide a branch-protection/ruleset write operation.
- Repository merge settings currently allow merge commits, rebase merges, and squash merges; server-side rules are therefore the appropriate place to constrain protected `main` behavior.
- The repository currently has no published GitHub Releases. The release workflow separately requires GitHub immutable-release enforcement before accepting a future production publication.
- The current PR workflows expose the check/job contexts `test (3.11.16)`, `test (3.12.14)`, `test (3.13.15)`, `analyze`, `capability-policy`, `capability-diff`, `state`, and `integrity`.

## Finding

The repository's source-controlled gates are strong, but GitHub is not currently enforcing them as a server-side merge/update boundary on `main`.

Because `main` is unprotected and no ruleset exists, an actor with sufficient repository write/admin authority can update `main` without GitHub first requiring the PR checks that the maintenance protocol expects. Likewise, there is no repository ruleset preventing update/deletion of production-style `v*.*.*` tags before an immutable release is published.

This is a control-plane gap, not a scanner-runtime defect. It does not change the 1.0.0 package/API/output contracts, but it weakens assurance that future source and release-tag updates must traverse the reviewed gates.

## Remediation prepared in this audit

- Added `docs/repository-governance.md` with the exact required branch/tag governance contract and current check names.
- Defined the required `main` ruleset behavior: PR-only updates, strict required checks, deletion protection, non-fast-forward protection, linear history, and no undocumented bypass actor.
- Defined production tag rules for `refs/tags/v*.*.*`: no update/move and no deletion after creation, without blocking creation of new version tags used to trigger the release workflow.
- Added explicit fresh-verification requirements and a fail-closed drift rule: unverifiable governance is `UNKNOWN`, never `SAFE`.
- Opened a tracked remediation issue so the server-side control cannot be silently forgotten.

## Why this audit is not marked COMPLETE

The connected GitHub tooling can read rulesets and branch state but does not expose the Administration-write operation required to create or edit repository rulesets/branch protection. No alternate installed plugin exposes that capability either.

Applying only repository files would not enforce the missing server-side boundary, so this audit is intentionally `NEEDS_ATTENTION` until the rulesets are configured through an authorized GitHub administration path and freshly verified.

## Required closure evidence

The remediation can be closed only when fresh GitHub state shows:

- `main` reports protected;
- an active branch ruleset targets the default branch;
- all current PR check contexts are required with strict/up-to-date enforcement;
- direct/force updates and deletion of `main` are blocked;
- an active tag ruleset targets `refs/tags/v*.*.*` and blocks update/deletion;
- bypass actors are reviewed and documented (preferably none);
- release immutability remains enforced for production publication;
- the tracked issue is completed only after those facts are re-read from GitHub.

## Residual risk

Repository owners/admins can change server-side governance settings outside source control. GitHub plan/features, ruleset semantics, repository ownership, and privileged actors remain external trust inputs. A source commit cannot by itself prove those controls are still active.

UNKNOWN external state is not SAFE.
