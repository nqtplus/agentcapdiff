import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]


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


def test_spdx_sbom_generation_is_reproducible_for_same_artifacts(tmp_path: Path):
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "agentcapdiff-0.9.0-py3-none-any.whl").write_bytes(b"wheel-bytes")
    (dist / "agentcapdiff-0.9.0.tar.gz").write_bytes(b"sdist-bytes")
    first = tmp_path / "first.spdx.json"
    second = tmp_path / "second.spdx.json"
    env = {**os.environ, "SOURCE_DATE_EPOCH": "1787731887"}

    for output in (first, second):
        result = subprocess.run(
            [
                sys.executable,
                "scripts/generate_sbom.py",
                "--root",
                str(ROOT),
                "--dist-dir",
                str(dist),
                "--output",
                str(output),
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr

    assert first.read_bytes() == second.read_bytes()
    payload = json.loads(first.read_text(encoding="utf-8"))
    assert payload["spdxVersion"] == "SPDX-2.3"
    assert payload["creationInfo"]["created"] == "2026-08-26T08:11:27Z"
    assert len(payload["files"]) == 2
    assert any(package["name"] == "PyYAML" for package in payload["packages"])
