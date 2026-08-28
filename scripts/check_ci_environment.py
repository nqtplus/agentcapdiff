from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "requirements" / "ci-environment.json"


def _fail(message: str) -> None:
    raise ValueError(message)


def _load_config() -> dict[str, object]:
    payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    required = (
        "runner_label",
        "runner_environment",
        "runner_os",
        "runner_arch",
        "image_os",
        "image_version",
        "os_id",
        "os_version",
        "ambient_python",
        "ambient_pip",
        "setup_pip",
        "setup_python_versions",
    )
    for key in required:
        if not payload.get(key):
            _fail(f"missing CI environment provenance key: {key}")
    return payload


def _os_release() -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        values[key] = value.strip().strip('"')
    return values


def check(
    expected_python: str | None = None,
    expected_pip: str | None = None,
) -> dict[str, str]:
    config = _load_config()
    expected_env = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": str(config["runner_environment"]),
        "RUNNER_OS": str(config["runner_os"]),
        "RUNNER_ARCH": str(config["runner_arch"]),
        "ImageOS": str(config["image_os"]),
        "ImageVersion": str(config["image_version"]),
    }
    observed_env: dict[str, str] = {}
    for name, expected in expected_env.items():
        actual = os.environ.get(name)
        if actual != expected:
            _fail(f"{name} provenance mismatch: expected {expected!r}, got {actual!r}")
        observed_env[name] = actual

    release = _os_release()
    if release.get("ID") != config["os_id"]:
        _fail(f"runner OS ID mismatch: {release.get('ID')!r}")
    if release.get("VERSION_ID") != config["os_version"]:
        _fail(f"runner OS version mismatch: {release.get('VERSION_ID')!r}")
    if platform.machine().lower() not in {"x86_64", "amd64"}:
        _fail(f"runner architecture mismatch: {platform.machine()!r}")

    python_version = platform.python_version()
    if expected_python is not None and python_version != expected_python:
        _fail(f"Python version mismatch: expected {expected_python}, got {python_version}")

    pip_version = importlib.metadata.version("pip")
    if expected_pip is not None and pip_version != expected_pip:
        _fail(f"pip version mismatch: expected {expected_pip}, got {pip_version}")

    return {
        "runner_environment": observed_env["RUNNER_ENVIRONMENT"],
        "runner_os": observed_env["RUNNER_OS"],
        "runner_arch": observed_env["RUNNER_ARCH"],
        "image_os": observed_env["ImageOS"],
        "image_version": observed_env["ImageVersion"],
        "os_version": release["VERSION_ID"],
        "python": python_version,
        "pip": pip_version,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify reviewed GitHub-hosted CI provenance.")
    parser.add_argument("--python-version")
    parser.add_argument("--pip-version")
    args = parser.parse_args(argv)
    try:
        evidence = check(args.python_version, args.pip_version)
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        importlib.metadata.PackageNotFoundError,
    ) as exc:
        print(f"ci-environment: FAIL: {exc}", file=sys.stderr)
        return 1
    print("ci-environment: PASS " + json.dumps(evidence, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
