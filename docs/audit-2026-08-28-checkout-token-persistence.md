# Audit 2026-08-28 — checkout token persistence

## Scope

Exactly one AUDIT pass covering GitHub Actions token exposure through `actions/checkout`, repository Git credential persistence, and reliance on post-job cleanup.

Reviewed all workflows under `.github/workflows/`, release token use, the release-integrity gate, and prior workflow behavior. This audit does not execute/import scanned target repository code, probe discovered endpoints, or collect credentials.

## Finding

Every workflow used `actions/checkout` without overriding its credential-persistence default. The checkout authentication material could therefore remain configured for repository Git operations during subsequent shell/build/test steps until checkout's post-job cleanup ran.

This was unnecessary for this repository:

- normal CI/PR jobs only need read checkout data;
- the release validation fetch targets this public repository;
- release publication already passes `${{ github.token }}` explicitly as `GH_TOKEN` only to `gh` steps that require it.

Relying only on cleanup after arbitrary later steps increases the credential exposure window and is weaker than not persisting the checkout credential in the first place.

## Fix

- Set `persist-credentials: false` on every `actions/checkout` step in all repository workflows.
- Keep existing least-privilege workflow/job permissions unchanged.
- Keep release write-token use step-scoped through `GH_TOKEN`; no token is added to general job environment or Git configuration by this change.
- Extend `scripts/check_release_integrity.py` so any future checkout lacking explicit `persist-credentials: false` fails the permanent integrity gate.
- Add a negative regression test proving the gate rejects a checkout step that relies on the persistence default.

## Compatibility

Package/runtime version remains `1.0.0`. Capability, policy, JSON, SARIF, snapshot, diff, benchmark, and CLI contracts are unchanged.

## Residual risk

Disabling checkout credential persistence reduces one token exposure path; it does not make GitHub-hosted runners, pinned third-party Actions, repository permissions, or explicitly token-bearing release steps risk-free. Post-job cleanup remains useful defense in depth. UNKNOWN is not SAFE.
