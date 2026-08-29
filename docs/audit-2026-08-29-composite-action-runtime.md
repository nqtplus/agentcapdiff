# Composite GitHub Action consumer/runtime audit — 2026-08-29

## Scope

This is one coherent post-v1.0 audit pass covering the repository-root composite Action (`action.yml`) as a consumer/runtime trust boundary:

- Action input handling and shell invocation;
- scan/policy path authority and working-directory semantics;
- installation/runtime isolation inside a caller workflow;
- dependency and source provenance used by the Action;
- output/file-command side channels;
- supported runner/Python contract;
- production pinning guidance and fail-closed behavior.

Baseline main before the audit:

`d44da7963668f706ec5165c0d9e75bab3f8efba0`

Package version, capability/policy semantics, JSON/SARIF contracts, and the static-scanner model remain v1.0.0.

## Baseline findings

### 1. Action inputs were interpolated directly into Bash source

The baseline composite Action executed:

```yaml
run: agentcapdiff scan "${{ inputs.path }}" --policy "${{ inputs.policy }}" --fail-on "${{ inputs.fail-on }}"
```

GitHub evaluates `${{ ... }}` expressions before handing the generated script to the shell. Shell quoting around the expression therefore does not turn attacker-controlled input into inert data; crafted input can change the generated shell program. GitHub's secure-use guidance recommends moving untrusted expression values into environment variables and consuming the environment variables from the script instead.

This is a genuine consumer-side script-injection surface whenever a caller lets untrusted data influence an Action input.

### 2. The Action mutated the caller Python environment and resolved dependencies dynamically

The baseline Action ran:

```text
python -m pip install "${{ github.action_path }}"
```

That installs into the caller-selected Python environment and allows the build/runtime dependency path to be resolved dynamically at Action execution time. Even with a reviewed immutable Action ref, the effective runtime therefore depended on external package resolution and caller environment state that were not bounded by the Action itself.

The repository's producer CI/release path already used reviewed exact pins and hashes, but the public composite Action did not inherit that fail-closed dependency model.

### 3. Action-level path authority was broader than the documented scan intent

The CLI itself deliberately supports normal local paths. For a reusable GitHub Action, however, `path` and `policy` are caller-controlled authority crossing from workflow metadata into filesystem reads.

The baseline wrapper did not independently require those Action inputs to resolve inside `GITHUB_WORKSPACE`. A non-empty missing policy path also reached the CLI behavior that falls back to built-in policy defaults. For an automated Action invocation, a mistyped configured policy should not silently weaken the intended policy boundary.

## Remediation

### Treat Action inputs as data, never shell program text

`action.yml` now maps `path`, `policy`, and `fail-on` to dedicated environment variables. The inline Bash program contains no `${{ inputs.* }}` expression and invokes one reviewed Python wrapper using the trusted `github.action_path` location.

A permanent Actions trust-boundary gate rejects any future direct Action-input interpolation in the inline shell source, direct `pip install`, mutable GitHub file-command channels, or unsafe execution primitives in the wrapper.

### Constrain scan and policy authority to the checked-out workspace

The wrapper resolves Action inputs before scanning:

- the scan path must exist, be a regular file/directory, and resolve inside `GITHUB_WORKSPACE`;
- a direct symlink scan target is rejected;
- a non-empty policy path must exist as a regular non-symlink file inside `GITHUB_WORKSPACE`;
- `policy: ""` is the explicit opt-in to built-in policy defaults;
- `fail-on` is accepted only as `never`, `medium`, or `high`.

This Action-specific boundary does not change the general CLI's existing local-path compatibility contract.

### Isolate the Action runtime from the caller environment

The wrapper creates a temporary virtual environment under `RUNNER_TEMP` instead of installing AgentCapDiff into the caller interpreter environment.

Only the runtime dependency closure is installed into that temporary environment. Installation is fail-closed with:

- exact package version;
- SHA-256 artifact hashes;
- `--require-hashes`;
- `--no-deps`;
- `--no-cache-dir`;
- `--only-binary=:all:`;
- an explicit package index;
- Python isolated mode for the wrapper/invocation.

`requirements/action-runtime-lock.txt` is permanently checked against the project runtime dependency set and against the corresponding reviewed hashes already present in `requirements/ci-lock.txt`.

The Action source itself is not rebuilt or installed. After the locked dependency is present, the wrapper places the trusted Action `src` directory first on a sanitized import path and removes caller-workspace import paths before importing AgentCapDiff. This avoids target-repository module shadowing while preserving the scanner's static behavior.

### Explicit supported runtime

The composite Action now fails closed unless it is running in GitHub Actions on Linux X64 with CPython 3.11, 3.12, or 3.13. CI exercises the local composite Action across all three supported Python patch versions.

Consumers remain responsible for selecting an appropriate trusted runner/Python environment and for granting the workflow only the permissions it actually needs. AgentCapDiff itself does not require write permissions for an ordinary scan.

### Consumer source pinning remains mandatory production guidance

Production callers should continue to use a reviewed full AgentCapDiff commit SHA or a reviewed verified immutable release tag. A floating branch does not provide source immutability.

The wrapper validates that the Action path exposed by GitHub matches the source tree executing the wrapper, but this check does not replace caller-side immutable source selection.

## Permanent regression coverage

This audit adds coverage that:

- rejects direct `${{ inputs.* }}` interpolation in the composite shell script;
- rejects direct package installation in that shell script;
- rejects scan paths escaping `GITHUB_WORKSPACE`;
- rejects a configured policy path that does not exist;
- accepts an explicitly empty policy only as an intentional built-in-default choice;
- rejects unsupported `fail-on` values and direct symlink scan targets;
- requires the Action runtime lock to exactly match project runtime pins and reviewed CI hashes;
- applies the reviewed GitHub Action supplier allowlist to root `action.yml` as well as workflow files;
- executes the composite Action itself in the normal CI matrix for Python 3.11, 3.12, and 3.13.

## Residual trust boundaries

- Caller workflow/job permissions, secrets, checkout choices, and surrounding steps remain outside the composite Action's authority.
- The GitHub Actions runner, Python/venv/pip implementations, TLS/DNS/package-index availability, and operating-system platform remain external trust roots.
- Hash pinning establishes the accepted package artifact bytes, not that those bytes are free of unknown defects.
- A maintainer still decides which future runtime versions and hashes enter the reviewed trust set.
- A caller may explicitly choose `fail-on: never`; that is visible caller policy, not a scanner claim that findings are safe.
- The Action is a static review aid, not a sandbox for untrusted code in the caller workflow.

`UNKNOWN` is not treated as safe.
