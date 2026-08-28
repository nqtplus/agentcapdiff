from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
import tomllib
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class ReleaseArtifactError(ValueError):
    """Raised when release artifacts or auxiliary outputs are unsafe or inconsistent."""


def _absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _require_real_directory(path: Path, label: str) -> Path:
    absolute = _absolute(path)
    try:
        resolved = absolute.resolve(strict=True)
        current_stat = absolute.lstat()
    except OSError as exc:
        raise ReleaseArtifactError(f"{label} is unavailable: {absolute}") from exc
    if not stat.S_ISDIR(current_stat.st_mode):
        raise ReleaseArtifactError(f"{label} must be a real directory: {absolute}")
    if os.path.normcase(str(resolved)) != os.path.normcase(str(absolute)):
        raise ReleaseArtifactError(f"{label} must not traverse symlinks: {absolute}")
    return resolved


def _open_regular(path: Path) -> int:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ReleaseArtifactError(f"release artifact must be a regular file: {path}")
    except BaseException:
        os.close(fd)
        raise
    return fd


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


def _read_regular_text(path: Path) -> str:
    fd = _open_regular(path)
    chunks: list[bytes] = []
    try:
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    return b"".join(chunks).decode("utf-8")


def _created_time() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    try:
        value = datetime.fromtimestamp(int(epoch), UTC) if epoch else datetime.now(UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise ReleaseArtifactError("SOURCE_DATE_EPOCH must be a valid Unix timestamp") from exc
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _dependency_name(requirement: str) -> str:
    match = re.match(r"^[A-Za-z0-9_.-]+", requirement.strip())
    if match is None:
        raise ReleaseArtifactError(f"unsupported dependency requirement: {requirement}")
    return match.group(0)


def _project(root: Path) -> dict[str, Any]:
    try:
        project = tomllib.loads(_read_regular_text(root / "pyproject.toml"))["project"]
    except (KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseArtifactError("cannot read project metadata for release artifacts") from exc
    if str(project.get("name", "")) != "agentcapdiff":
        raise ReleaseArtifactError("release artifact generator is restricted to agentcapdiff")
    if not str(project.get("version", "")):
        raise ReleaseArtifactError("project version is missing")
    return project


def _release_artifacts(dist_dir: Path, version: str) -> list[Path]:
    dist = _require_real_directory(dist_dir, "release dist directory")
    expected = {
        f"agentcapdiff-{version}-py3-none-any.whl",
        f"agentcapdiff-{version}.tar.gz",
    }
    entries = sorted(dist.iterdir(), key=lambda item: item.name)
    names = {entry.name for entry in entries}
    if names != expected:
        missing = sorted(expected - names)
        unexpected = sorted(names - expected)
        details = []
        if missing:
            details.append(f"missing={missing}")
        if unexpected:
            details.append(f"unexpected={unexpected}")
        raise ReleaseArtifactError("release artifact set mismatch: " + ", ".join(details))

    for artifact in entries:
        try:
            artifact_stat = artifact.lstat()
        except OSError as exc:
            raise ReleaseArtifactError(f"cannot inspect release artifact: {artifact}") from exc
        if stat.S_ISLNK(artifact_stat.st_mode) or not stat.S_ISREG(artifact_stat.st_mode):
            raise ReleaseArtifactError(f"release artifact must be a non-symlink regular file: {artifact}")
    return entries


def build_sbom(root: Path, dist_dir: Path) -> dict[str, Any]:
    root = _require_real_directory(root, "release root")
    project = _project(root)
    name = str(project["name"])
    version = str(project["version"])
    artifacts = _release_artifacts(dist_dir, version)

    file_records: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-AgentCapDiff",
        }
    ]
    artifact_fingerprint = hashlib.sha256()
    for index, artifact in enumerate(artifacts, start=1):
        checksum = _sha256_regular(artifact)
        artifact_fingerprint.update(artifact.name.encode("utf-8"))
        artifact_fingerprint.update(checksum.encode("ascii"))
        file_id = f"SPDXRef-File-{index}"
        file_records.append(
            {
                "fileName": f"./{artifact.name}",
                "SPDXID": file_id,
                "checksums": [{"algorithm": "SHA256", "checksumValue": checksum}],
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-AgentCapDiff",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": file_id,
            }
        )

    packages: list[dict[str, Any]] = [
        {
            "name": name,
            "SPDXID": "SPDXRef-Package-AgentCapDiff",
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "copyrightText": "NOASSERTION",
        }
    ]
    for index, requirement in enumerate(project.get("dependencies", []), start=1):
        dependency = _dependency_name(str(requirement))
        dependency_id = f"SPDXRef-Dependency-{index}"
        packages.append(
            {
                "name": dependency,
                "SPDXID": dependency_id,
                "versionInfo": str(requirement),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "copyrightText": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "spdxElementId": "SPDXRef-Package-AgentCapDiff",
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": dependency_id,
            }
        )

    fingerprint = artifact_fingerprint.hexdigest()
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{name}-{version}-release-sbom",
        "documentNamespace": (
            "https://github.com/nqtplus/agentcapdiff/sbom/" f"{version}/{fingerprint}"
        ),
        "creationInfo": {
            "created": _created_time(),
            "creators": ["Tool: agentcapdiff-v0.9-sbom-generator"],
        },
        "packages": packages,
        "files": file_records,
        "relationships": relationships,
    }


def _checksum_manifest(payload: dict[str, Any]) -> str:
    lines = []
    for record in payload["files"]:
        filename = str(record["fileName"]).removeprefix("./")
        checksum = str(record["checksums"][0]["checksumValue"])
        lines.append(f"{checksum}  {filename}")
    return "\n".join(lines) + "\n"


def _validate_output_target(path: Path) -> Path:
    target = _absolute(path)
    parent = _require_real_directory(target.parent, "release output directory")
    candidate = parent / target.name
    try:
        target_stat = candidate.lstat()
    except FileNotFoundError:
        return candidate
    except OSError as exc:
        raise ReleaseArtifactError(f"cannot inspect release output: {candidate}") from exc
    if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
        raise ReleaseArtifactError(f"release output must be a non-symlink regular file: {candidate}")
    return candidate


def _atomic_write_text(target: Path, text: str) -> None:
    parent = target.parent
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.agentcapdiff-", dir=parent)
    temp = Path(temp_name)
    try:
        payload = text.encode("utf-8")
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise OSError("short write while creating release metadata")
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = -1

        _validate_output_target(target)
        os.replace(temp, target)
    finally:
        if fd >= 0:
            os.close(fd)
        with suppress(FileNotFoundError):
            temp.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate validated SPDX/checksum release metadata.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checksums-output", type=Path)
    args = parser.parse_args(argv)

    try:
        root = _require_real_directory(args.root, "release root")
        dist_dir = args.dist_dir if args.dist_dir.is_absolute() else root / args.dist_dir
        output = _validate_output_target(args.output)
        checksums_output = (
            _validate_output_target(args.checksums_output) if args.checksums_output else None
        )
        if checksums_output is not None and checksums_output == output:
            raise ReleaseArtifactError("SBOM and checksum outputs must be different files")

        payload = build_sbom(root, dist_dir)
        _atomic_write_text(output, json.dumps(payload, indent=2, sort_keys=True) + "\n")
        if checksums_output is not None:
            _atomic_write_text(checksums_output, _checksum_manifest(payload))
    except (OSError, ReleaseArtifactError) as exc:
        print(f"release-assets: FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
