import hashlib
import json
import os
import pathlib
import runpy
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
VERSION = "1.0.0"
WHEEL = f"agentcapdiff-{VERSION}-py3-none-any.whl"
SDIST = f"agentcapdiff-{VERSION}.tar.gz"
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
CHECK_RELEASE_INTEGRITY = runpy.run_path(
    str(ROOT / "scripts" / "check_release_integrity.py"),
    run_name="check_release_integrity",
)


def _run_generator(
    dist: pathlib.Path,
    output: pathlib.Path,
    checksums: pathlib.Path | None = None,
    *,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        "scripts/generate_sbom.py",
        "--root",
        str(ROOT),
        "--dist-dir",
        str(dist),
        "--output",
        str(output),
    ]
    if checksums is not None:
        command.extend(["--checksums-output", str(checksums)])
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _make_release_dist(tmp_path: pathlib.Path) -> pathlib.Path:
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / WHEEL).write_bytes(b"wheel-bytes")
    (dist / SDIST).write_bytes(b"sdist-bytes")
    return dist


def test_release_integrity_contract_passes_for_repository():
    result = subprocess.run(
        [sys.executable, "scripts/check_release_integrity.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "release-integrity: PASS" in result.stdout


def test_release_integrity_rejects_checkout_credential_persistence(tmp_path: pathlib.Path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow = workflow_dir / "unsafe.yml"
    workflow.write_text(
        "name: unsafe\n"
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        f"      - uses: actions/checkout@{CHECKOUT_SHA}\n",
        encoding="utf-8",
    )
    check_workflow_action_pins = CHECK_RELEASE_INTEGRITY["_check_workflow_action_pins"]

    with pytest.raises(ValueError, match="persist-credentials: false"):
        check_workflow_action_pins(tmp_path)


def test_dependency_lock_rejects_non_exact_transitive_pin(tmp_path: pathlib.Path):
    requirements = tmp_path / "requirements"
    requirements.mkdir()
    (requirements / "ci-direct.txt").write_text("pytest==9.1.1\n", encoding="utf-8")
    (requirements / "ci-lock.txt").write_text(
        "pytest==9.1.1\npluggy>=1.6.0\n",
        encoding="utf-8",
    )
    check_dependency_lock = CHECK_RELEASE_INTEGRITY["_check_dependency_lock"]

    with pytest.raises(ValueError, match="not an exact package pin"):
        check_dependency_lock(tmp_path)


def test_dependency_lock_rejects_direct_version_mismatch(tmp_path: pathlib.Path):
    requirements = tmp_path / "requirements"
    requirements.mkdir()
    (requirements / "ci-direct.txt").write_text("pytest==9.1.1\n", encoding="utf-8")
    (requirements / "ci-lock.txt").write_text(
        "pytest==9.1.0\npluggy==1.6.0\n",
        encoding="utf-8",
    )
    check_dependency_lock = CHECK_RELEASE_INTEGRITY["_check_dependency_lock"]

    with pytest.raises(ValueError, match="must contain direct pin pytest==9.1.1"):
        check_dependency_lock(tmp_path)


def test_dependency_workflow_contract_rejects_pip_cache(tmp_path: pathlib.Path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (workflow_dir / "unsafe.yml").write_text(
        "jobs:\n"
        "  test:\n"
        "    steps:\n"
        "      - uses: actions/setup-python@0123456789012345678901234567890123456789\n"
        "        with:\n"
        "          cache: pip\n",
        encoding="utf-8",
    )
    check_dependency_workflow_contract = CHECK_RELEASE_INTEGRITY[
        "_check_dependency_workflow_contract"
    ]

    with pytest.raises(ValueError, match="pip cache is forbidden"):
        check_dependency_workflow_contract(tmp_path)


def test_spdx_and_checksums_are_reproducible_for_same_exact_artifacts(
    tmp_path: pathlib.Path,
):
    dist = _make_release_dist(tmp_path)
    first = tmp_path / "first.spdx.json"
    second = tmp_path / "second.spdx.json"
    first_sums = tmp_path / "first.SHA256SUMS"
    second_sums = tmp_path / "second.SHA256SUMS"
    env = {**os.environ, "SOURCE_DATE_EPOCH": "1787731887"}

    for output, checksums in ((first, first_sums), (second, second_sums)):
        result = _run_generator(dist, output, checksums, env=env)
        assert result.returncode == 0, result.stderr

    assert first.read_bytes() == second.read_bytes()
    assert first_sums.read_bytes() == second_sums.read_bytes()
    payload = json.loads(first.read_text(encoding="utf-8"))
    assert payload["spdxVersion"] == "SPDX-2.3"
    assert payload["creationInfo"]["created"] == "2026-08-26T08:11:27Z"
    assert len(payload["files"]) == 2
    assert any(package["name"] == "PyYAML" for package in payload["packages"])

    expected = {
        WHEEL: hashlib.sha256(b"wheel-bytes").hexdigest(),
        SDIST: hashlib.sha256(b"sdist-bytes").hexdigest(),
    }
    manifest_lines = first_sums.read_text(encoding="utf-8").splitlines()
    assert set(manifest_lines) == {f"{digest}  {name}" for name, digest in expected.items()}
    sbom_hashes = {
        record["fileName"].removeprefix("./"): record["checksums"][0]["checksumValue"]
        for record in payload["files"]
    }
    assert sbom_hashes == expected


def test_release_generator_rejects_unexpected_dist_entry(tmp_path: pathlib.Path):
    dist = _make_release_dist(tmp_path)
    (dist / "unexpected.txt").write_text("not a release artifact", encoding="utf-8")
    output = tmp_path / "release.spdx.json"

    result = _run_generator(dist, output)

    assert result.returncode == 1
    assert "release artifact set mismatch" in result.stderr
    assert not output.exists()


def test_release_generator_rejects_symlink_artifact(tmp_path: pathlib.Path):
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")
    dist = tmp_path / "dist"
    dist.mkdir()
    victim = tmp_path / "outside.whl"
    victim.write_bytes(b"outside-bytes")
    os.symlink(victim, dist / WHEEL)
    (dist / SDIST).write_bytes(b"sdist-bytes")
    output = tmp_path / "release.spdx.json"

    result = _run_generator(dist, output)

    assert result.returncode == 1
    assert "non-symlink regular file" in result.stderr
    assert victim.read_bytes() == b"outside-bytes"
    assert not output.exists()


def test_release_generator_rejects_symlink_output_without_touching_target(
    tmp_path: pathlib.Path,
):
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")
    dist = _make_release_dist(tmp_path)
    victim = tmp_path / "victim.json"
    victim.write_text("keep-me", encoding="utf-8")
    output = tmp_path / "release.spdx.json"
    os.symlink(victim, output)

    result = _run_generator(dist, output)

    assert result.returncode == 1
    assert "non-symlink regular file" in result.stderr
    assert victim.read_text(encoding="utf-8") == "keep-me"


def test_release_generator_rejects_symlinked_output_parent(tmp_path: pathlib.Path):
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")
    dist = _make_release_dist(tmp_path)
    real_release = tmp_path / "real-release"
    real_release.mkdir()
    redirected = tmp_path / "release"
    os.symlink(real_release, redirected, target_is_directory=True)

    result = _run_generator(dist, redirected / "agentcapdiff.spdx.json")

    assert result.returncode == 1
    assert "release output directory" in result.stderr
    assert list(real_release.iterdir()) == []


def test_release_generator_prevalidates_both_outputs_before_writing(tmp_path: pathlib.Path):
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks unavailable")
    dist = _make_release_dist(tmp_path)
    output = tmp_path / "agentcapdiff.spdx.json"
    victim = tmp_path / "victim.sums"
    victim.write_text("keep-me", encoding="utf-8")
    checksums = tmp_path / "SHA256SUMS"
    os.symlink(victim, checksums)

    result = _run_generator(dist, output, checksums)

    assert result.returncode == 1
    assert not output.exists()
    assert victim.read_text(encoding="utf-8") == "keep-me"
