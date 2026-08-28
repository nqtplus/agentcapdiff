from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
import tomllib
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
USES_RE = re.compile(r"^\s*-\s+uses:\s*([^\s#]+)", re.MULTILINE)
CHECKOUT_RE = re.compile(
    r"^(?P<indent>\s*)-\s+uses:\s*actions/checkout@([^\s#]+)"
)
PERSIST_FALSE_RE = re.compile(
    r"^\s*persist-credentials:\s*false\s*(?:#.*)?$",
    re.IGNORECASE,
)
VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"$', re.MULTILINE)
PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^\s;]+)$"
)
RUNS_ON_RE = re.compile(r"^\s*runs-on:\s*([^\s#]+)\s*$", re.MULTILINE)
SCALAR_PYTHON_RE = re.compile(
    r'^\s*python-version:\s*"(?P<version>\d+\.\d+(?:\.\d+)?)"\s*$',
    re.MULTILINE,
)
LOCK_INSTALL = (
    "python -m pip --isolated --disable-pip-version-check install --require-hashes "
    "--no-deps --no-cache-dir --only-binary=:all: "
    "--index-url=https://pypi.org/simple -r requirements/ci-lock.txt"
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
            _fail(
                f"{label} contains non-local or conditional requirement "
                f"at line {line_number}"
            )
        match = PIN_RE.fullmatch(line)
        if match is None:
            _fail(
                f"{label} requirement is not an exact package pin "
                f"at line {line_number}: {line}"
            )
        name = _normalize_package_name(match.group("name"))
        version = match.group("version")
        if name in pins:
            _fail(f"{label} contains duplicate package pin: {name}")
        pins[name] = version
    if not pins:
        _fail(f"{label} has no package pins")
    return pins


def _logical_requirement_lines(path: Path) -> list[tuple[int, str]]:
    logical: list[tuple[int, str]] = []
    buffer: list[str] = []
    start_line = 0
    for line_number, raw in enumerate(_read(path).splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if not buffer:
            start_line = line_number
        continued = line.endswith("\\")
        if continued:
            line = line[:-1].rstrip()
        buffer.append(line)
        if not continued:
            logical.append((start_line, " ".join(buffer)))
            buffer = []
    if buffer:
        _fail(f"dependency lock has dangling line continuation at line {start_line}")
    return logical


def _parse_hashed_lock(path: Path) -> dict[str, tuple[str, tuple[str, ...]]]:
    pins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for line_number, logical in _logical_requirement_lines(path):
        tokens = shlex.split(logical)
        if not tokens:
            continue
        requirement = tokens[0]
        if " @ " in requirement or "://" in requirement or ";" in requirement:
            _fail(
                "CI dependency lock contains remote or conditional input "
                f"at line {line_number}"
            )
        match = PIN_RE.fullmatch(requirement)
        if match is None:
            _fail(
                "CI dependency lock requirement is not an exact package pin "
                f"at line {line_number}: {requirement}"
            )
        name = _normalize_package_name(match.group("name"))
        version = match.group("version")
        hashes: list[str] = []
        for token in tokens[1:]:
            prefix = "--hash=sha256:"
            if not token.startswith(prefix):
                _fail(
                    "CI dependency lock has unsupported option "
                    f"at line {line_number}: {token}"
                )
            digest = token.removeprefix(prefix)
            if not SHA256_RE.fullmatch(digest):
                _fail(f"CI dependency lock has invalid SHA-256 at line {line_number}")
            if digest in hashes:
                _fail(f"CI dependency lock repeats a SHA-256 at line {line_number}")
            hashes.append(digest)
        if not hashes:
            _fail(
                "CI dependency lock pin lacks artifact SHA-256 "
                f"at line {line_number}: {name}"
            )
        if name in pins:
            _fail(f"CI dependency lock contains duplicate package pin: {name}")
        pins[name] = (version, tuple(hashes))
    if not pins:
        _fail("CI dependency lock has no package pins")
    return pins


def _load_ci_environment(root: Path) -> dict[str, object]:
    path = root / "requirements" / "ci-environment.json"
    payload = json.loads(_read(path))
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
            _fail(f"CI environment provenance key must be a non-empty string: {key}")

    runner_label = str(payload["runner_label"])
    if "latest" in runner_label:
        _fail(f"CI runner label must not use a moving alias: {runner_label}")
    if re.fullmatch(r"ubuntu-\d+\.\d+", runner_label) is None:
        _fail(f"CI runner label must pin an Ubuntu release: {runner_label}")

    image_version = str(payload["image_version"])
    if re.fullmatch(r"\d{8}\.\d+\.\d+", image_version) is None:
        _fail("CI image_version must be an exact reviewed runner image version")

    versions = payload.get("setup_python_versions")
    if not isinstance(versions, list) or not versions:
        _fail("CI setup_python_versions must be a non-empty list")
    for version in versions:
        if not isinstance(version, str):
            _fail(f"CI setup-python version must be a string: {version!r}")
        if re.fullmatch(r"\d+\.\d+\.\d+", version) is None:
            _fail(f"CI setup-python version must include an exact patch: {version!r}")
    if len(set(versions)) != len(versions):
        _fail("CI setup_python_versions contains a duplicate")
    return payload


def _python_matrix_fragment(config: dict[str, object]) -> str:
    versions = config["setup_python_versions"]
    assert isinstance(versions, list)
    rendered = ", ".join(f'"{version}"' for version in versions)
    return f"python-version: [{rendered}]"


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
                _fail(
                    f"Action reference missing immutable ref in {workflow.name}: "
                    f"{reference}"
                )
            action, ref = reference.rsplit("@", 1)
            if not SHA_RE.fullmatch(ref):
                _fail(
                    f"Action must be pinned to a full commit SHA in {workflow.name}: "
                    f"{action}@{ref}"
                )


def _check_dependency_lock(root: Path) -> None:
    direct = _parse_exact_pins(
        root / "requirements" / "ci-direct.txt",
        "CI direct pins",
    )
    locked = _parse_hashed_lock(root / "requirements" / "ci-lock.txt")
    for name, version in direct.items():
        locked_entry = locked.get(name)
        if locked_entry is None or locked_entry[0] != version:
            _fail(f"CI dependency lock must contain direct pin {name}=={version}")
    if len(locked) <= len(direct):
        _fail("CI dependency lock must freeze the transitive closure, not only direct pins")


def _check_ci_environment_contract(root: Path) -> None:
    config = _load_ci_environment(root)
    runner_label = str(config["runner_label"])
    setup_versions = {str(item) for item in config["setup_python_versions"]}
    setup_pip = str(config["setup_pip"])
    ambient_python = str(config["ambient_python"])
    ambient_pip = str(config["ambient_pip"])
    matrix_fragment = _python_matrix_fragment(config)

    workflow_dir = root / ".github" / "workflows"
    for workflow in sorted(workflow_dir.glob("*.y*ml")):
        text = _read(workflow)
        runners = RUNS_ON_RE.findall(text)
        if not runners:
            _fail(f"workflow has no explicit runner: {workflow.name}")
        if any(runner != runner_label for runner in runners):
            _fail(f"workflow runner must be {runner_label}: {workflow.name}")

        provenance_count = text.count("scripts/check_ci_environment.py")
        if provenance_count != len(runners):
            _fail(
                "each workflow job must verify reviewed runner provenance: "
                f"{workflow.name}"
            )

        setup_count = text.count("actions/setup-python@")
        setup_pip_count = text.count(f'--pip-version "{setup_pip}"')
        if setup_pip_count != setup_count:
            _fail(
                "each setup-python job must verify reviewed pip bootstrap: "
                f"{workflow.name}"
            )

        ambient_command = (
            f'--python-version "{ambient_python}" '
            f'--pip-version "{ambient_pip}"'
        )
        ambient_count = text.count(ambient_command)
        if ambient_count != len(runners) - setup_count:
            _fail(
                "each ambient-Python job must verify Python and pip provenance: "
                f"{workflow.name}"
            )

        if setup_count:
            uses_matrix = "python-version: ${{ matrix.python-version }}" in text
            if uses_matrix and matrix_fragment not in text:
                _fail(
                    "setup-python matrix must use reviewed exact patches: "
                    f"{workflow.name}"
                )
            for match in SCALAR_PYTHON_RE.finditer(text):
                version = match.group("version")
                if version not in setup_versions:
                    _fail(
                        "setup-python scalar must use a reviewed exact patch in "
                        f"{workflow.name}: {version}"
                    )

    _read(root / "scripts" / "check_ci_environment.py")


def _check_dependency_workflow_contract(root: Path) -> None:
    workflow_dir = root / ".github" / "workflows"
    for workflow in sorted(workflow_dir.glob("*.y*ml")):
        text = _read(workflow)
        if "cache: pip" in text:
            _fail(f"pip cache is forbidden for locked installs: {workflow.name}")
        if "requirements/ci-direct.txt" in text:
            _fail(
                "workflow must install the full dependency lock, not direct pins: "
                f"{workflow.name}"
            )
        install_count = text.count(LOCK_INSTALL)
        lock_reference_count = text.count("requirements/ci-lock.txt")
        if lock_reference_count != install_count:
            _fail(
                f"workflow has an unapproved dependency-lock invocation: {workflow.name}"
            )
        check_count = text.count("python -m pip check")
        if install_count != check_count:
            _fail(
                "each hashed dependency install must be followed by pip check in "
                f"{workflow.name}"
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
                "workflow uses Python build/runtime tooling without hashed dependencies: "
                f"{workflow.name}"
            )


def _check_dependency_maintenance(root: Path) -> None:
    dependabot = _read(root / ".github" / "dependabot.yml")
    if 'package-ecosystem: "pip"' not in dependabot:
        _fail("Dependabot pip updates are not configured")
    if 'package-ecosystem: "github-actions"' not in dependabot:
        _fail("Dependabot GitHub Actions updates are not configured")
    _check_dependency_lock(root)
    _check_ci_environment_contract(root)
    _check_dependency_workflow_contract(root)


def _check_release_workflow(root: Path) -> None:
    release = _read(root / ".github" / "workflows" / "release.yml")
    config = _load_ci_environment(root)
    required_fragments = (
        "permissions: {}",
        _python_matrix_fragment(config),
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
        "ubuntu-latest",
    )
    for fragment in forbidden_fragments:
        if fragment in release:
            _fail(f"release workflow uses an unconstrained integrity input: {fragment}")


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
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
    ) as exc:
        print(f"release-integrity: FAIL: {exc}", file=sys.stderr)
        return 1
    print(f"release-integrity: PASS version={version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
