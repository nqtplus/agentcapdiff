from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
USES_RE = re.compile(r"^\s*-\s+uses:\s*([^\s#]+)", re.MULTILINE)
CHECKOUT_RE = re.compile(r"^(?P<indent>\s*)-\s+uses:\s*actions/checkout@([^\s#]+)")
PERSIST_FALSE_RE = re.compile(r"^\s*persist-credentials:\s*false\s*(?:#.*)?$", re.IGNORECASE)
VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"$', re.MULTILINE)
PIN_RE = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^\s;]+)$")
LOCK_INSTALL = (
    "python -m pip install --no-deps --no-cache-dir --only-binary=:all: "
    "-r requirements/ci-lock.txt"
)


def _fail(message: str) -> None:
    raise ValueError(message)


def _read(path: Path) -> str:
    if not path.is_file():
        _fail(f"required release-integrity file missing: {path.as_posix()}")
    return path.read_text(encoding="utf-8")


def _normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_exact_pins(path: Path, label: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line_number, raw in enumerate(_read(path).splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if " @ " in line or "://" in line or line.startswith("git+") or ";" in line:
            _fail(f"{label} contains non-local or conditional requirement at line {line_number}")
        match = PIN_RE.fullmatch(line)
        if match is None:
            _fail(f"{label} requirement is not an exact package pin at line {line_number}: {line}")
        name = _normalize_package_name(match.group("name"))
        version = match.group("version")
        if name in pins:
            _fail(f"{label} contains duplicate package pin: {name}")
        pins[name] = version
    if not pins:
        _fail(f"{label} has no package pins")
    return pins


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


def _checkout_step_blocks(text: str) -> list[tuple[int, list[str]]]:
    lines = text.splitlines()
    blocks: list[tuple[int, list[str]]] = []
    for index, line in enumerate(lines):
        match = CHECKOUT_RE.match(line)
        if match is None:
            continue
        indent = len(match.group("indent"))
        body: list[str] = []
        for following in lines[index + 1 :]:
            if not following.strip():
                body.append(following)
                continue
            leading = len(following) - len(following.lstrip())
            if leading <= indent:
                break
            body.append(following)
        blocks.append((index + 1, body))
    return blocks


def _check_checkout_credential_persistence(workflow: Path, text: str) -> None:
    for line_number, body in _checkout_step_blocks(text):
        if not any(PERSIST_FALSE_RE.match(line) for line in body):
            _fail(
                "actions/checkout must set persist-credentials: false "
                f"in {workflow.name}:{line_number}"
            )


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
        _check_checkout_credential_persistence(workflow, text)
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


def _check_dependency_lock(root: Path) -> None:
    direct = _parse_exact_pins(root / "requirements" / "ci-direct.txt", "CI direct pins")
    locked = _parse_exact_pins(root / "requirements" / "ci-lock.txt", "CI dependency lock")
    for name, version in direct.items():
        if locked.get(name) != version:
            _fail(f"CI dependency lock must contain direct pin {name}=={version}")
    if len(locked) <= len(direct):
        _fail("CI dependency lock must freeze the transitive closure, not only direct pins")


def _check_dependency_workflow_contract(root: Path) -> None:
    workflow_dir = root / ".github" / "workflows"
    for workflow in sorted(workflow_dir.glob("*.y*ml")):
        text = _read(workflow)
        if "cache: pip" in text:
            _fail(f"pip cache is forbidden for locked CI/release installs: {workflow.name}")
        if "requirements/ci-direct.txt" in text:
            _fail(
                "workflow must install the full dependency lock, not direct pins: "
                f"{workflow.name}"
            )
        install_count = text.count(LOCK_INSTALL)
        check_count = text.count("python -m pip check")
        if install_count != check_count:
            _fail(
                f"each locked dependency install must be followed by a pip check in {workflow.name}"
            )
        needs_dependencies = any(
            fragment in text
            for fragment in (
                "python -m pip install . --no-deps --no-build-isolation",
                "python -m build --no-isolation",
            )
        )
        if needs_dependencies and install_count == 0:
            _fail(
                "workflow uses Python build/runtime tooling without locked dependencies: "
                f"{workflow.name}"
            )


def _check_dependency_maintenance(root: Path) -> None:
    dependabot = _read(root / ".github" / "dependabot.yml")
    if 'package-ecosystem: "pip"' not in dependabot:
        _fail("Dependabot pip updates are not configured")
    if 'package-ecosystem: "github-actions"' not in dependabot:
        _fail("Dependabot GitHub Actions updates are not configured")
    _check_dependency_lock(root)
    _check_dependency_workflow_contract(root)


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
