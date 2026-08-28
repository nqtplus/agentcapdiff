from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

REPOSITORY = "nqtplus/agentcapdiff"
SIGNER_WORKFLOW = f"{REPOSITORY}/.github/workflows/release.yml"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
SLSA_PREDICATE = "https://slsa.dev/provenance/v1"
SPDX_PREDICATE = "https://spdx.dev/Document/v2.3"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
TAG_RE = re.compile(r"^v(?P<version>\d+\.\d+\.\d+)$")
CHECKSUM_RE = re.compile(r"^(?P<digest>[0-9a-f]{64}) (?P<mode>[ *])(?P<name>[^\r\n]+)$")
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_ERROR_CHARS = 4000


class ReleaseVerificationError(ValueError):
    """Raised when release provenance cannot be verified fail-closed."""


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _open_regular(path: Path) -> int:
    absolute = _absolute(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(absolute, flags)
    except OSError as exc:
        raise ReleaseVerificationError(f"cannot open regular file: {absolute}") from exc
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ReleaseVerificationError(f"expected regular file: {absolute}")
    except BaseException:
        os.close(fd)
        raise
    return fd


def _read_regular_bytes(path: Path, *, limit: int = MAX_METADATA_BYTES) -> bytes:
    fd = _open_regular(path)
    chunks: list[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(fd, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise ReleaseVerificationError(f"metadata file exceeds {limit} bytes: {path}")
    finally:
        os.close(fd)
    return b"".join(chunks)


def _sha256_regular(path: Path) -> str:
    digest = hashlib.sha256()
    fd = _open_regular(path)
    try:
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest()


def _release_version(tag: str) -> str:
    match = TAG_RE.fullmatch(tag)
    if match is None:
        raise ReleaseVerificationError(f"release tag must be exact vX.Y.Z: {tag!r}")
    return match.group("version")


def _expected_artifact_names(tag: str) -> tuple[str, str]:
    version = _release_version(tag)
    return (
        f"agentcapdiff-{version}-py3-none-any.whl",
        f"agentcapdiff-{version}.tar.gz",
    )


def _parse_checksums(path: Path, expected_names: set[str]) -> dict[str, str]:
    try:
        text = _read_regular_bytes(path, limit=1024 * 1024).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseVerificationError("SHA256SUMS must be valid UTF-8") from exc

    checksums: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = CHECKSUM_RE.fullmatch(line)
        if match is None:
            raise ReleaseVerificationError(
                f"invalid SHA256SUMS entry at line {line_number}: {line!r}"
            )
        name = match.group("name")
        if Path(name).name != name or name in {".", ".."}:
            raise ReleaseVerificationError(
                f"SHA256SUMS subject name must be a basename at line {line_number}: {name!r}"
            )
        if name in checksums:
            raise ReleaseVerificationError(f"duplicate SHA256SUMS subject: {name}")
        checksums[name] = match.group("digest")

    if set(checksums) != expected_names:
        raise ReleaseVerificationError(
            "SHA256SUMS subject set mismatch: "
            f"expected={sorted(expected_names)!r}, got={sorted(checksums)!r}"
        )
    return checksums


def _load_sbom(path: Path, checksums: dict[str, str]) -> dict[str, Any]:
    try:
        payload = json.loads(_read_regular_bytes(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseVerificationError("release SBOM must be valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or payload.get("spdxVersion") != "SPDX-2.3":
        raise ReleaseVerificationError("release SBOM must be an SPDX-2.3 document")

    files = payload.get("files")
    if not isinstance(files, list):
        raise ReleaseVerificationError("release SBOM files must be a list")
    observed: dict[str, str] = {}
    for record in files:
        if not isinstance(record, dict):
            raise ReleaseVerificationError("release SBOM file record must be an object")
        name = record.get("fileName")
        if not isinstance(name, str):
            raise ReleaseVerificationError("release SBOM fileName must be a string")
        name = name.removeprefix("./")
        if Path(name).name != name or name in observed:
            raise ReleaseVerificationError(f"invalid or duplicate release SBOM subject: {name!r}")
        values = record.get("checksums")
        if not isinstance(values, list):
            raise ReleaseVerificationError(f"release SBOM checksums missing for {name}")
        sha256_values = [
            item.get("checksumValue")
            for item in values
            if isinstance(item, dict) and item.get("algorithm") == "SHA256"
        ]
        if len(sha256_values) != 1 or not isinstance(sha256_values[0], str):
            raise ReleaseVerificationError(f"release SBOM needs one SHA256 for {name}")
        observed[name] = sha256_values[0]

    if observed != checksums:
        raise ReleaseVerificationError("release SBOM artifact hashes do not match SHA256SUMS")
    return payload


def _verification_command(
    artifact: Path,
    tag: str,
    source_sha: str,
    predicate_type: str,
    bundle: Path | None = None,
) -> list[str]:
    command = [
        "gh",
        "attestation",
        "verify",
        str(artifact),
        "--repo",
        REPOSITORY,
        "--signer-workflow",
        SIGNER_WORKFLOW,
        "--source-ref",
        f"refs/tags/{tag}",
        "--source-digest",
        source_sha,
        "--signer-digest",
        source_sha,
        "--cert-oidc-issuer",
        OIDC_ISSUER,
        "--predicate-type",
        predicate_type,
        "--deny-self-hosted-runners",
        "--format",
        "json",
        "--limit",
        "30",
    ]
    if bundle is not None:
        command.extend(["--bundle", str(bundle)])
    return command


def _run_verification(command: list[str]) -> list[dict[str, Any]]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except OSError as exc:
        raise ReleaseVerificationError(f"cannot execute GitHub CLI: {exc}") from exc
    if result.returncode != 0:
        diagnostic = (result.stderr or result.stdout).strip()[-MAX_ERROR_CHARS:]
        raise ReleaseVerificationError(f"GitHub attestation verification failed: {diagnostic}")
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ReleaseVerificationError(
            "GitHub attestation verification returned invalid JSON"
        ) from exc
    if not isinstance(payload, list) or not payload:
        raise ReleaseVerificationError(
            "GitHub attestation verification returned no verified result"
        )
    if not all(isinstance(item, dict) for item in payload):
        raise ReleaseVerificationError("GitHub attestation verification returned malformed results")
    return payload


def _result_matches_subject(
    result: dict[str, Any],
    *,
    artifact_name: str,
    digest: str,
    predicate_type: str,
) -> bool:
    verification = result.get("verificationResult")
    if not isinstance(verification, dict):
        return False
    statement = verification.get("statement")
    if not isinstance(statement, dict) or statement.get("predicateType") != predicate_type:
        return False
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        return False
    for subject in subjects:
        if not isinstance(subject, dict) or subject.get("name") != artifact_name:
            continue
        digests = subject.get("digest")
        if isinstance(digests, dict) and digests.get("sha256") == digest:
            return True
    return False


def _require_verified_subject(
    results: list[dict[str, Any]],
    *,
    artifact_name: str,
    digest: str,
    predicate_type: str,
    expected_predicate: dict[str, Any] | None = None,
) -> None:
    for result in results:
        if not _result_matches_subject(
            result,
            artifact_name=artifact_name,
            digest=digest,
            predicate_type=predicate_type,
        ):
            continue
        if expected_predicate is None:
            return
        verification = result["verificationResult"]
        statement = verification["statement"]
        if statement.get("predicate") == expected_predicate:
            return
    if expected_predicate is None:
        raise ReleaseVerificationError(
            f"verified attestation does not bind expected subject {artifact_name}"
        )
    raise ReleaseVerificationError(
        f"verified SPDX attestation does not bind the published SBOM for {artifact_name}"
    )


def verify_release(
    *,
    tag: str,
    source_sha: str,
    dist_dir: Path,
    checksums_path: Path,
    sbom_path: Path,
    provenance_bundle: Path | None = None,
    sbom_bundle: Path | None = None,
) -> None:
    if SHA_RE.fullmatch(source_sha) is None:
        raise ReleaseVerificationError("source SHA must be an exact 40-character Git commit")
    expected_names = set(_expected_artifact_names(tag))
    checksums = _parse_checksums(checksums_path, expected_names)
    sbom = _load_sbom(sbom_path, checksums)

    if provenance_bundle is not None:
        _read_regular_bytes(provenance_bundle)
    if sbom_bundle is not None:
        _read_regular_bytes(sbom_bundle)

    for name in sorted(expected_names):
        artifact = dist_dir / name
        digest = _sha256_regular(artifact)
        if digest != checksums[name]:
            raise ReleaseVerificationError(f"artifact hash does not match SHA256SUMS: {name}")

        provenance_results = _run_verification(
            _verification_command(
                artifact,
                tag,
                source_sha,
                SLSA_PREDICATE,
                provenance_bundle,
            )
        )
        _require_verified_subject(
            provenance_results,
            artifact_name=name,
            digest=digest,
            predicate_type=SLSA_PREDICATE,
        )

        sbom_results = _run_verification(
            _verification_command(
                artifact,
                tag,
                source_sha,
                SPDX_PREDICATE,
                sbom_bundle,
            )
        )
        _require_verified_subject(
            sbom_results,
            artifact_name=name,
            digest=digest,
            predicate_type=SPDX_PREDICATE,
            expected_predicate=sbom,
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fail-closed verification of AgentCapDiff release attestations."
    )
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--checksums", type=Path, default=Path("release/SHA256SUMS"))
    parser.add_argument("--sbom", type=Path, default=Path("release/agentcapdiff.spdx.json"))
    parser.add_argument("--provenance-bundle", type=Path)
    parser.add_argument("--sbom-bundle", type=Path)
    args = parser.parse_args(argv)
    try:
        verify_release(
            tag=args.tag,
            source_sha=args.source_sha,
            dist_dir=args.dist_dir,
            checksums_path=args.checksums,
            sbom_path=args.sbom,
            provenance_bundle=args.provenance_bundle,
            sbom_bundle=args.sbom_bundle,
        )
    except (OSError, ReleaseVerificationError) as exc:
        print(f"release-attestation: FAIL: {exc}", file=sys.stderr)
        return 1
    print(
        "release-attestation: PASS "
        f"repo={REPOSITORY} tag={args.tag} source={args.source_sha}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
