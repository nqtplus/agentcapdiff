import json
import pathlib
import runpy

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = runpy.run_path(
    str(ROOT / "scripts" / "check_ci_environment.py"),
    run_name="check_ci_environment_allowlist",
)
CONFIG = json.loads(
    (ROOT / "requirements" / "ci-environment.json").read_text(encoding="utf-8")
)


def _set_reviewed_runner(monkeypatch: pytest.MonkeyPatch, image_version: str) -> None:
    values = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": CONFIG["runner_environment"],
        "RUNNER_OS": CONFIG["runner_os"],
        "RUNNER_ARCH": CONFIG["runner_arch"],
        "ImageOS": CONFIG["image_os"],
        "ImageVersion": image_version,
    }
    for key, value in values.items():
        monkeypatch.setenv(key, str(value))

    check = CHECKER["check"]
    monkeypatch.setitem(
        check.__globals__,
        "_os_release",
        lambda: {"ID": CONFIG["os_id"], "VERSION_ID": CONFIG["os_version"]},
    )
    monkeypatch.setattr(check.__globals__["platform"], "machine", lambda: "x86_64")
    monkeypatch.setattr(
        check.__globals__["platform"],
        "python_version",
        lambda: CONFIG["ambient_python"],
    )
    monkeypatch.setattr(
        check.__globals__["importlib"].metadata,
        "version",
        lambda name: CONFIG["ambient_pip"] if name == "pip" else "unexpected",
    )


def test_canonical_runner_image_is_in_reviewed_allowlist():
    assert CONFIG["image_version"] in CONFIG["image_versions"]
    assert len(CONFIG["image_versions"]) == len(set(CONFIG["image_versions"]))


def test_ci_environment_accepts_reviewed_fleet_skew(monkeypatch: pytest.MonkeyPatch):
    older_reviewed = "20260628.225.1"
    assert older_reviewed in CONFIG["image_versions"]
    _set_reviewed_runner(monkeypatch, older_reviewed)

    evidence = CHECKER["check"](
        CONFIG["ambient_python"],
        CONFIG["ambient_pip"],
    )

    assert evidence["image_version"] == older_reviewed


def test_ci_environment_rejects_unreviewed_runner_image(monkeypatch: pytest.MonkeyPatch):
    _set_reviewed_runner(monkeypatch, "20990101.1.1")

    with pytest.raises(ValueError, match="ImageVersion provenance mismatch"):
        CHECKER["check"](
            CONFIG["ambient_python"],
            CONFIG["ambient_pip"],
        )
