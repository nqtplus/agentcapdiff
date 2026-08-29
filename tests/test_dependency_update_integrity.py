import pathlib
import runpy
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECK = runpy.run_path(
    str(ROOT / "scripts" / "check_dependency_update_integrity.py"),
    run_name="check_dependency_update_integrity",
)
FULL_SHA = "a" * 40


def _safe_dependabot_config() -> str:
    return """version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 0
    labels:
      - "dependencies"

  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 3
    cooldown:
      default-days: 7
    allow:
      - dependency-name: "actions/checkout"
      - dependency-name: "actions/setup-python"
      - dependency-name: "actions/attest"
      - dependency-name: "github/codeql-action"
    labels:
      - "dependencies"
"""


def _write_minimal_project(root: pathlib.Path, *, pyyaml: str = "6.0.3") -> None:
    (root / "requirements").mkdir(parents=True)
    (root / "requirements" / "ci-direct.txt").write_text(
        f"PyYAML=={pyyaml}\n"
        "build==1.5.0\n"
        "hatchling==1.32.0\n"
        "pytest==9.1.1\n"
        "pytest-cov==7.1.0\n"
        "ruff==0.16.4\n",
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        "[build-system]\n"
        'requires = ["hatchling==1.32.0"]\n'
        'build-backend = "hatchling.build"\n\n'
        "[project]\n"
        'name = "example"\n'
        'version = "1.0.0"\n'
        'dependencies = ["PyYAML==6.0.3"]\n\n'
        "[project.optional-dependencies]\n"
        'dev = ["pytest==9.1.1", "pytest-cov==7.1.0", "ruff==0.16.4"]\n',
        encoding="utf-8",
    )


def _copy_runtime_lock_contract(root: pathlib.Path) -> None:
    (root / "requirements").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "pyproject.toml", root / "pyproject.toml")
    for name in ("action-runtime-lock.txt", "ci-lock.txt"):
        shutil.copyfile(ROOT / "requirements" / name, root / "requirements" / name)


def test_dependency_update_contract_passes_for_repository():
    result = subprocess.run(
        [sys.executable, "scripts/check_dependency_update_integrity.py", "--root", "."],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "dependency-update-integrity: PASS" in result.stdout


def test_manifest_consistency_rejects_version_drift(tmp_path: pathlib.Path):
    _write_minimal_project(tmp_path, pyyaml="6.0.2")
    check_manifest = CHECK["_check_manifest_consistency"]

    with pytest.raises(ValueError, match="must match pyproject exactly"):
        check_manifest(tmp_path)


def test_manifest_consistency_rejects_unreviewed_direct_tool(tmp_path: pathlib.Path):
    _write_minimal_project(tmp_path)
    direct = tmp_path / "requirements" / "ci-direct.txt"
    direct.write_text(
        direct.read_text(encoding="utf-8") + "mystery-tool==1.0.0\n",
        encoding="utf-8",
    )
    check_manifest = CHECK["_check_manifest_consistency"]

    with pytest.raises(ValueError, match="unexpected=.*mystery-tool"):
        check_manifest(tmp_path)


def test_action_runtime_lock_rejects_version_drift(tmp_path: pathlib.Path):
    _copy_runtime_lock_contract(tmp_path)
    lock = tmp_path / "requirements" / "action-runtime-lock.txt"
    lock.write_text(
        lock.read_text(encoding="utf-8").replace("PyYAML==6.0.3", "PyYAML==6.0.2"),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="version must match pyproject"):
        CHECK["_check_action_runtime_lock"](tmp_path)


def test_action_runtime_lock_rejects_hash_drift(tmp_path: pathlib.Path):
    _copy_runtime_lock_contract(tmp_path)
    lock = tmp_path / "requirements" / "action-runtime-lock.txt"
    source = lock.read_text(encoding="utf-8")
    first_hash = "b8bb0864c5a28024fac8a632c443c87c5aa6f215c0b126c449ae1a150412f31d"
    lock.write_text(source.replace(first_hash, "f" * 64), encoding="utf-8")

    with pytest.raises(ValueError, match="hashes must match reviewed CI lock hashes"):
        CHECK["_check_action_runtime_lock"](tmp_path)


def test_dependabot_policy_disables_routine_pip_version_prs(tmp_path: pathlib.Path):
    config_dir = tmp_path / ".github"
    config_dir.mkdir()
    unsafe = _safe_dependabot_config().replace(
        "open-pull-requests-limit: 0",
        "open-pull-requests-limit: 5",
        1,
    )
    (config_dir / "dependabot.yml").write_text(unsafe, encoding="utf-8")
    check_dependabot = CHECK["_check_dependabot_policy"]

    with pytest.raises(ValueError, match="open-pull-requests-limit: 0"):
        check_dependabot(tmp_path)


def test_dependabot_policy_rejects_registry_or_target_branch_expansion(
    tmp_path: pathlib.Path,
):
    config_dir = tmp_path / ".github"
    config_dir.mkdir()
    unsafe = _safe_dependabot_config() + 'target-branch: "automation"\n'
    (config_dir / "dependabot.yml").write_text(unsafe, encoding="utf-8")
    check_dependabot = CHECK["_check_dependabot_policy"]

    with pytest.raises(ValueError, match="target-branch"):
        check_dependabot(tmp_path)


def test_action_supplier_allowlist_rejects_arbitrary_full_sha(tmp_path: pathlib.Path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "unsafe.yml").write_text(
        "jobs:\n"
        "  scan:\n"
        "    steps:\n"
        f"      - uses: attacker/example@{FULL_SHA}\n",
        encoding="utf-8",
    )
    (tmp_path / "action.yml").write_text(
        "name: safe\nruns:\n  using: composite\n  steps: []\n",
        encoding="utf-8",
    )
    check_suppliers = CHECK["_check_action_suppliers"]

    with pytest.raises(ValueError, match="unreviewed Action supplier"):
        check_suppliers(tmp_path)


def test_composite_action_supplier_is_also_allowlisted(tmp_path: pathlib.Path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "safe.yml").write_text("jobs: {}\n", encoding="utf-8")
    (tmp_path / "action.yml").write_text(
        "name: unsafe\nruns:\n  using: composite\n  steps:\n"
        f"    - uses: attacker/composite@{FULL_SHA}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unreviewed Action supplier"):
        CHECK["_check_action_suppliers"](tmp_path)


def test_dependabot_changed_paths_accept_only_dependency_surfaces():
    check_paths = CHECK["check_changed_paths"]
    check_paths(
        [
            "pyproject.toml",
            "requirements/action-runtime-lock.txt",
            "requirements/ci-lock.txt",
            ".github/workflows/ci.yml",
        ]
    )


def test_dependabot_changed_paths_reject_source_or_policy_mutation():
    check_paths = CHECK["check_changed_paths"]

    with pytest.raises(ValueError, match="forbidden path"):
        check_paths(["src/agentcapdiff/cli.py"])
    with pytest.raises(ValueError, match="forbidden path"):
        check_paths([".github/dependabot.yml"])
