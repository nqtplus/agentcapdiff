import pathlib
import runpy
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECK = runpy.run_path(
    str(ROOT / "scripts" / "check_actions_trust_boundaries.py"),
    run_name="check_actions_trust_boundaries",
)


def test_actions_trust_boundary_contract_passes_for_repository():
    result = subprocess.run(
        [sys.executable, "scripts/check_actions_trust_boundaries.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "actions-trust-boundaries: PASS" in result.stdout


def test_rejects_pull_request_target_trigger(tmp_path: pathlib.Path):
    workflow = tmp_path / "unsafe.yml"
    workflow.write_text("on:\n  pull_request_target:\n", encoding="utf-8")
    check_global = CHECK["_check_global_event_and_side_channels"]

    with pytest.raises(ValueError, match="privilege-crossing trigger"):
        check_global(workflow, workflow.read_text(encoding="utf-8"))


def test_rejects_artifact_handoff_side_channel(tmp_path: pathlib.Path):
    workflow = tmp_path / "unsafe.yml"
    workflow.write_text(
        "on:\n  pull_request:\nsteps:\n"
        "  - uses: actions/upload-artifact@0123456789012345678901234567890123456789\n",
        encoding="utf-8",
    )
    check_global = CHECK["_check_global_event_and_side_channels"]

    with pytest.raises(ValueError, match="cache/artifact side channel"):
        check_global(workflow, workflow.read_text(encoding="utf-8"))


def test_rejects_mutable_file_command_in_write_capable_pr_job(tmp_path: pathlib.Path):
    workflow = tmp_path / "unsafe.yml"
    workflow.write_text(
        "on:\n  pull_request:\npermissions:\n  security-events: write\n"
        "jobs:\n  scan:\n    steps:\n      - run: echo bad >> \"$GITHUB_ENV\"\n",
        encoding="utf-8",
    )
    check_global = CHECK["_check_global_event_and_side_channels"]

    with pytest.raises(ValueError, match="mutable file-command channel GITHUB_ENV"):
        check_global(workflow, workflow.read_text(encoding="utf-8"))


def test_static_workflow_rejects_package_install_outside_trusted_step(
    tmp_path: pathlib.Path,
):
    source = (ROOT / ".github" / "workflows" / "agentcapdiff.yml").read_text(
        encoding="utf-8"
    )
    source = source.replace(
        "      - name: Install trusted base package\n"
        "        working-directory: ../agentcapdiff-trusted-base\n"
        "        run: python -m pip install . --no-deps --no-build-isolation\n",
        "      - name: Install trusted base package\n"
        "        working-directory: ../agentcapdiff-trusted-base\n"
        "        run: echo trusted-install-removed\n"
        "      - name: Candidate install\n"
        "        run: python -m pip install . --no-deps --no-build-isolation\n",
    )
    workflow = tmp_path / "agentcapdiff.yml"
    workflow.write_text(source, encoding="utf-8")
    check_static = CHECK["_check_trusted_static_workflow"]

    with pytest.raises(ValueError, match="package install escaped trusted-base step"):
        check_static(workflow, sarif_upload=True)


def test_candidate_execution_workflow_must_remain_read_only(tmp_path: pathlib.Path):
    workflow = tmp_path / "ci.yml"
    workflow.write_text(
        "on:\n  pull_request:\npermissions:\n  contents: write\n",
        encoding="utf-8",
    )
    check_read_only = CHECK["_check_read_only_candidate_execution"]

    with pytest.raises(ValueError, match="must remain read-only"):
        check_read_only(workflow)
