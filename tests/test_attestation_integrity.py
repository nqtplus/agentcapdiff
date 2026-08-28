import hashlib
import json
import pathlib
import runpy
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
CHECKER = runpy.run_path(
    str(ROOT / "scripts" / "check_attestation_integrity.py"),
    run_name="check_attestation_integrity",
)
VERIFIER = runpy.run_path(
    str(ROOT / "scripts" / "verify_release_attestations.py"),
    run_name="verify_release_attestations",
)


def test_attestation_integrity_contract_passes_for_repository():
    result = subprocess.run(
        [sys.executable, "scripts/check_attestation_integrity.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "attestation-integrity: PASS" in result.stdout


def test_attestation_contract_rejects_subject_glob(tmp_path: pathlib.Path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    release = release.replace(
        "subject-checksums: release/SHA256SUMS",
        'subject-path: "dist/*"',
        1,
    )
    (workflow_dir / "release.yml").write_text(release, encoding="utf-8")
    check_release_workflow = CHECKER["_check_release_workflow"]

    with pytest.raises(ValueError, match="subject-checksums|subject-path"):
        check_release_workflow(tmp_path)


def test_attestation_contract_rejects_missing_prepublication_verifier(tmp_path: pathlib.Path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    release = release.replace(
        "python scripts/verify_release_attestations.py",
        "python scripts/verify_release_DISABLED.py",
        1,
    )
    (workflow_dir / "release.yml").write_text(release, encoding="utf-8")
    check_release_workflow = CHECKER["_check_release_workflow"]

    with pytest.raises(ValueError, match="missing required control"):
        check_release_workflow(tmp_path)


def test_verification_command_pins_repo_workflow_ref_commit_runner_and_predicate():
    command = VERIFIER["_verification_command"](
        pathlib.Path("dist/agentcapdiff-1.0.0-py3-none-any.whl"),
        "v1.0.0",
        "a" * 40,
        VERIFIER["SLSA_PREDICATE"],
        pathlib.Path("bundle.jsonl"),
    )
    joined = " ".join(command)

    assert "--repo nqtplus/agentcapdiff" in joined
    assert (
        "--signer-workflow nqtplus/agentcapdiff/.github/workflows/release.yml" in joined
    )
    assert "--source-ref refs/tags/v1.0.0" in joined
    assert f"--source-digest {'a' * 40}" in joined
    assert f"--signer-digest {'a' * 40}" in joined
    assert "--cert-oidc-issuer https://token.actions.githubusercontent.com" in joined
    assert "--deny-self-hosted-runners" in command
    assert "--predicate-type https://slsa.dev/provenance/v1" in joined
    assert "--bundle bundle.jsonl" in joined


def test_checksum_manifest_rejects_path_subject(tmp_path: pathlib.Path):
    path = tmp_path / "SHA256SUMS"
    path.write_text(f"{'a' * 64}  ../artifact.whl\n", encoding="utf-8")
    parse_checksums = VERIFIER["_parse_checksums"]

    with pytest.raises(ValueError, match="basename|subject set mismatch"):
        parse_checksums(path, {"artifact.whl"})


def test_verified_spdx_result_must_match_exact_subject_and_published_sbom():
    digest = "b" * 64
    sbom = {"spdxVersion": "SPDX-2.3", "files": []}
    result = {
        "verificationResult": {
            "statement": {
                "predicateType": VERIFIER["SPDX_PREDICATE"],
                "subject": [
                    {
                        "name": "agentcapdiff-1.0.0-py3-none-any.whl",
                        "digest": {"sha256": digest},
                    }
                ],
                "predicate": sbom,
            }
        }
    }
    require_verified_subject = VERIFIER["_require_verified_subject"]

    require_verified_subject(
        [result],
        artifact_name="agentcapdiff-1.0.0-py3-none-any.whl",
        digest=digest,
        predicate_type=VERIFIER["SPDX_PREDICATE"],
        expected_predicate=sbom,
    )
    with pytest.raises(ValueError, match="published SBOM"):
        require_verified_subject(
            [result],
            artifact_name="agentcapdiff-1.0.0-py3-none-any.whl",
            digest=digest,
            predicate_type=VERIFIER["SPDX_PREDICATE"],
            expected_predicate={"spdxVersion": "SPDX-2.3", "files": [{"changed": True}]},
        )


def test_release_verifier_rejects_local_artifact_hash_drift_before_gh(
    tmp_path: pathlib.Path,
):
    tag = "v1.0.0"
    wheel = "agentcapdiff-1.0.0-py3-none-any.whl"
    sdist = "agentcapdiff-1.0.0.tar.gz"
    dist = tmp_path / "dist"
    release = tmp_path / "release"
    dist.mkdir()
    release.mkdir()
    (dist / wheel).write_bytes(b"changed-wheel")
    (dist / sdist).write_bytes(b"sdist")
    expected = {
        wheel: hashlib.sha256(b"original-wheel").hexdigest(),
        sdist: hashlib.sha256(b"sdist").hexdigest(),
    }
    (release / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in expected.items()),
        encoding="utf-8",
    )
    sbom = {
        "spdxVersion": "SPDX-2.3",
        "files": [
            {
                "fileName": f"./{name}",
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest}],
            }
            for name, digest in expected.items()
        ],
    }
    (release / "agentcapdiff.spdx.json").write_text(json.dumps(sbom), encoding="utf-8")
    verify_release = VERIFIER["verify_release"]

    with pytest.raises(ValueError, match="artifact hash does not match SHA256SUMS"):
        verify_release(
            tag=tag,
            source_sha="c" * 40,
            dist_dir=dist,
            checksums_path=release / "SHA256SUMS",
            sbom_path=release / "agentcapdiff.spdx.json",
        )
