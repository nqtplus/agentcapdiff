import pathlib
import runpy

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
WRAPPER = runpy.run_path(
    str(ROOT / "scripts" / "run_composite_action.py"),
    run_name="run_composite_action_tests",
)


def test_validate_inputs_accepts_workspace_and_explicit_empty_policy(
    tmp_path: pathlib.Path,
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "tools.json").write_text("{}\n", encoding="utf-8")

    scan, policy, fail_on = WRAPPER["validate_inputs"](
        workspace,
        "tools.json",
        "",
        "medium",
    )

    assert scan == "tools.json"
    assert policy is None
    assert fail_on == "medium"


def test_validate_inputs_rejects_scan_path_escape(tmp_path: pathlib.Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()

    with pytest.raises(ValueError, match="escapes GITHUB_WORKSPACE"):
        WRAPPER["validate_inputs"](workspace, "../outside", "", "medium")


def test_validate_inputs_rejects_missing_nonempty_policy(tmp_path: pathlib.Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "tools.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="policy path does not resolve"):
        WRAPPER["validate_inputs"](
            workspace,
            "tools.json",
            "missing-policy.yaml",
            "medium",
        )


def test_validate_inputs_rejects_invalid_fail_on(tmp_path: pathlib.Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "tools.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="fail-on must be one of"):
        WRAPPER["validate_inputs"](
            workspace,
            "tools.json",
            "",
            "critical; echo unsafe",
        )


def test_validate_inputs_rejects_symlinked_scan_target(tmp_path: pathlib.Path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    real = workspace / "real.json"
    real.write_text("{}\n", encoding="utf-8")
    link = workspace / "link.json"
    try:
        link.symlink_to(real.name)
    except OSError:
        pytest.skip("symlinks unavailable on this platform")

    with pytest.raises(ValueError, match="must not be a symlink"):
        WRAPPER["validate_inputs"](workspace, "link.json", "", "medium")
