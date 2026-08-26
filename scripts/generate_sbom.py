from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tomllib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _created_time() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    value = datetime.fromtimestamp(int(epoch), UTC) if epoch else datetime.now(UTC)
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _dependency_name(requirement: str) -> str:
    match = re.match(r"^[A-Za-z0-9_.-]+", requirement.strip())
    if match is None:
        raise ValueError(f"unsupported dependency requirement: {requirement}")
    return match.group(0)


def build_sbom(root: Path, dist_dir: Path) -> dict[str, Any]:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    name = str(project["name"])
    version = str(project["version"])
    artifacts = sorted(path for path in dist_dir.iterdir() if path.is_file())
    if not artifacts:
        raise ValueError(f"no release artifacts found in {dist_dir}")

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
        checksum = _sha256(artifact)
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
            "https://github.com/nqtplus/agentcapdiff/sbom/"
            f"{version}/{fingerprint}"
        ),
        "creationInfo": {
            "created": _created_time(),
            "creators": ["Tool: agentcapdiff-v0.9-sbom-generator"],
        },
        "packages": packages,
        "files": file_records,
        "relationships": relationships,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate an SPDX 2.3 release SBOM.")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--dist-dir", type=Path, default=Path("dist"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    dist_dir = (
        args.dist_dir
        if args.dist_dir.is_absolute()
        else (root / args.dist_dir).resolve()
    )
    payload = build_sbom(root, dist_dir)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
