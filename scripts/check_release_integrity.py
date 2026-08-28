from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*-\s+uses:\s*([^\s#]+)", re.MULTILINE)
VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"$', re.MULTILINE)


def _fail(message: str) -> None:
    raise ValueError(message)


def _read(path: Path) -> str:
    if not path.is_file():
        _fail(f"required release-integrity file missing: {path.as_posix()}")
    return path.read_text(encoding="utf-8")


def _project_version(root: Path) -> str:
    data = tomllib.loads(_read(root / "pyproject.toml"))
    version = str(data.get("project", {}).get("version", ""))
    if not version:
        _fail("project.version missing from pyproject.toml")

    build_requires = data.get("build-system", {}).get("requires", [])
    if not build_requires:
        _fail("build-system.requires must be explicit")
    for requirement in build_requires:
        if "==" not in str(requirement):
            _fail(f"build dependency is not exactly pinned: {requirement}")
    return version


def _check_versions(root: Path, version: str, release_tag: str | None) -> None:
    init_text = _read(root / "src" / "agentcapdiff" / "__init__.py")
    runtime = VERSION_RE.search(init_text)
    if runtime is None or runtime.group(1) != version:
        _fail("pyproject/runtime version mismatch")
    if release_tag is None:
        return
    if version.endswith(".dev0"):
        _fail("release tag cannot target a .dev0 package version")
    if release_tag != f"v{version}":
        _fail(f"release tag {release_tag!r} must exactly match v{version}")


def _check_release_project_state(root: Path, version: str) -> None:
    parts = version.split(".")
    if len(parts) < 2:
        _fail(f"unsupported release version: {version}")
    label = f"v{parts[0]}.{parts[1]}"

    roadmap = _read(root / "ROADMAP.md")
    pattern = rf"## {re.escape(label)} — ([^\n]+)(.*?)(?=\n## v\d|\Z)"
    match = re.search(pattern, roadmap, re.DOTALL)
    if match is None:
        _fail(f"ROADMAP.md lacks {label} section")
    title, body = match.groups()
    if "✅" not in title or "- [ ]" in body:
        _fail(f"{label} must be complete with no unchecked roadmap item")

    readme = _read(root / "README.md")
    status_pattern = rf"Status:\s*\*\*{re.escape(label)}\.0[^*]*complete\.\*\*"
    if re.search(status_pattern, readme, re.IGNORECASE) is None:
        _fail(f"README does not declare {label}.0 complete")

    changelog = _read(root / "CHANGELOG.md")
    if f"## [{version}]" not in changelog:
        _fail(f"CHANGELOG.md lacks [{version}] release entry")


def _check_workflow_action_pins(root: Path) -> None:
    workflow_dir = root / ".github" / "workflows"
    workflows = sorted(workflow_dir.glob("*.y*ml"))
    if not workflows:
        _fail("no GitHub Actions workflows found")
    for workflow in workflows:
        text = _read(workflow)
        if "pull_request_target:" in text:
            _fail(f"unsafe pull_request_target trigger is forbidden: {workflow.name}")
        if "write-all" in text:
            _fail(f"write-all permission is forbidden: {workflow.name}")
        for reference in USES_RE.findall(text):
            if reference.startswith("./"):
                continue
            if "@" not in reference:
                _fail(f"Action reference missing immutable ref in {workflow.name}: {reference}")
            action, ref = reference.rsplit("@", 1)
            if not SHA_RE.fullmatch(ref):
                _fail(
                    f"Action must be pinned to a full commit SHA in {workflow.name}: "
                    f"{action}@{ref}"
                )


def _check_dependency_maintenance(root: Path) -> None:
    dependabot = _read(root / ".github" / "dependabot.yml")
    if 'package-ecosystem: "pip"' not in dependabot:
        _fail("Dependabot pip updates are not configured")
    if 'package-ecosystem: "github-actions"' not in dependabot:
        _fail("Dependabot GitHub Actions updates are not configured")

    pins = _read(root / "requirements" / "ci-direct.txt")
    entries = [
        line.strip()
        for line in pins.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    if not entries:
        _fail("requirements/ci-direct.txt has no dependency pins")
    for entry in entries:
        unsafe = " @ " in entry or "://" in entry or entry.startswith("git+")
        if "==" not in entry or unsafe:
            _fail(f"CI direct dependency is not a reviewed exact package pin: {entry}")


def _check_release_workflow(root: Path) -> None:
    release = _read(root / ".github" / "workflows" / "release.yml")
    required_fragments = (
        "permissions: {}",
        'python-version: ["3.11", "3.12", "3.13"]',
        "merge-base --is-ancestor",
        "attestations: write",
        "id-token: write",
        "contents: write",
        "rm -rf -- dist release",
        "mkdir -- dist release",
        "python -m build --no-isolation --outdir dist",
        "python scripts/generate_sbom.py",
        "--checksums-output release/SHA256SUMS",
        "actions/attest@",
        'version="${GITHUB_REF_NAME#v}"',
        '"dist/agentcapdiff-${version}-py3-none-any.whl"',
        '"dist/agentcapdiff-${version}.tar.gz"',
        "release/agentcapdiff.spdx.json",
        "release/SHA256SUMS",
        "gh release create",
        "isImmutable",
    )
    for fragment in required_fragments:
        if fragment not in release:
            _fail(f"release workflow missing required integrity control: {fragment}")

    forbidden_fragments = (
        "sha256sum dist/*",
        "dist/* release/*",
    )
    for fragment in forbidden_fragments:
        if fragment in release:
            _fail(f"release workflow uses an unconstrained artifact pattern: {fragment}")


def check(root: Path, release_tag: str | None = None) -> str:
    root = root.resolve()
    version = _project_version(root)
    _check_versions(root, version, release_tag)
    _check_workflow_action_pins(root)
    _check_dependency_maintenance(root)
    _check_release_workflow(root)
    _read(root / "docs" / "security-review-v0.9.md")
    _read(root / "docs" / "release-integrity.md")
    if release_tag is not None:
        _check_release_project_state(root, version)
    return version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify AgentCapDiff release-integrity invariants."
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--release-tag")
    args = parser.parse_args(argv)
    try:
        version = check(args.root, args.release_tag)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"release-integrity: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"release-integrity: PASS version={version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
