from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "requirements" / "ci-environment.json"
IMAGE_VERSION_RE = re.compile(r"^\d{8}\.\d+\.\d+$")


def _fail(message: str) -> None:
    raise ValueError(message)


def _load_config() -> dict[str, object]:
    payload = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    required_strings = (
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
    )
    for key in required_strings:
        value = payload.get(key)
        if not isinstance(value, str) or not value:
            _fail(f"missing or invalid CI environment provenance key: {key}")

    image_versions = payload.get("image_versions")
    if not isinstance(image_versions, list) or not image_versions:
        _fail("CI image_versions must be a non-empty reviewed allowlist")
    for version in image_versions:
        if not isinstance(version, str) or IMAGE_VERSION_RE.fullmatch(version) is None:
            _fail(f"invalid reviewed CI image version: {version!r}")
    if len(set(image_versions)) != len(image_versions):
        _fail("CI image_versions contains a duplicate")
    if payload["image_version"] not in image_versions:
        _fail("canonical CI image_version must be present in image_versions")

    setup_versions = payload.get("setup_python_versions")
    if not isinstance(setup_versions, list) or not setup_versions:
        _fail("CI setup_python_versions must be a non-empty list")
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
    }
    observed_env: dict[str, str] = {}
    for name, expected in expected_env.items():
        actual = os.environ.get(name)
        if actual != expected:
            _fail(f"{name} provenance mismatch: expected {expected!r}, got {actual!r}")
        observed_env[name] = actual

    # GitHub's hosted runner contract exposes this mixed-case environment name.
    actual_image = os.environ.get("ImageVersion")  # noqa: SIM112
    reviewed_images = config["image_versions"]
    assert isinstance(reviewed_images, list)
    if actual_image not in reviewed_images:
        _fail(
            "ImageVersion provenance mismatch: expected one of "
            f"{reviewed_images!r}, got {actual_image!r}"
        )
    observed_env["ImageVersion"] = actual_image

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
