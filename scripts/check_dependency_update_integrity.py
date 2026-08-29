from __future__ import annotations

import argparse
import re
import shlex
import subprocess
import sys
import tomllib
from pathlib import Path


class DependencyUpdateIntegrityError(ValueError):
    """Raised when dependency/update automation escapes the reviewed trust boundary."""


SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^\s;]+)$"
)
USES_RE = re.compile(r"^\s*-\s+uses:\s*([^\s#]+)", re.MULTILINE)
WORKFLOW_PATH_RE = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")
MAX_GIT_DIFF_BYTES = 1_000_000

# Adding a new third-party Action supplier is a security decision, not a routine
# dependency bump. This allowlist is deliberately code-owned so a candidate PR
# cannot weaken it merely by editing a data/config file in the repository root.
ALLOWED_ACTIONS = frozenset(
    {
        "actions/attest",
        "actions/checkout",
        "actions/setup-python",
        "github/codeql-action/analyze",
        "github/codeql-action/init",
        "github/codeql-action/upload-sarif",
    }
)

# build is CI/release tooling rather than a declared project/runtime dependency.
# Every other direct CI pin must be declared with the exact same version in
# pyproject.toml.
MAINTENANCE_ONLY_DIRECT = frozenset({"build"})

# Dependabot is allowed to touch dependency manifests/locks and workflow Action
# references only. It must never be a general-purpose source/config editor.
DEPENDABOT_EXACT_PATHS = frozenset(
    {
        "pyproject.toml",
        "requirements/action-runtime-lock.txt",
        "requirements/ci-direct.txt",
        "requirements/ci-lock.txt",
    }
)


def _fail(message: str) -> None:
    raise DependencyUpdateIntegrityError(message)


def _read(path: Path) -> str:
    if not path.is_file():
        _fail(f"required dependency-integrity file missing: {path.as_posix()}")
    return path.read_text(encoding="utf-8")


def _normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_pin(requirement: object, label: str) -> tuple[str, str]:
    if not isinstance(requirement, str):
        _fail(f"{label} requirement must be a string: {requirement!r}")
    text = requirement.strip()
    if " @ " in text or "://" in text or text.startswith("git+") or ";" in text:
        _fail(f"{label} contains non-local or conditional requirement: {text}")
    match = PIN_RE.fullmatch(text)
    if match is None:
        _fail(f"{label} requirement is not an exact package pin: {text}")
    return _normalize_package_name(match.group("name")), match.group("version")


def _parse_pin_file(path: Path, label: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line_number, raw in enumerate(_read(path).splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, version = _parse_pin(line, f"{label} line {line_number}")
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
        _fail(f"hashed dependency lock has dangling continuation at line {start_line}")
    return logical


def _parse_hashed_lock(path: Path, label: str) -> dict[str, tuple[str, tuple[str, ...]]]:
    pins: dict[str, tuple[str, tuple[str, ...]]] = {}
    for line_number, logical in _logical_requirement_lines(path):
        tokens = shlex.split(logical)
        if not tokens:
            continue
        name, version = _parse_pin(tokens[0], f"{label} line {line_number}")
        hashes: list[str] = []
        for token in tokens[1:]:
            prefix = "--hash=sha256:"
            if not token.startswith(prefix):
                _fail(f"{label} has unsupported option at line {line_number}: {token}")
            digest = token.removeprefix(prefix)
            if SHA256_RE.fullmatch(digest) is None:
                _fail(f"{label} has invalid SHA-256 at line {line_number}")
            if digest in hashes:
                _fail(f"{label} repeats a SHA-256 at line {line_number}")
            hashes.append(digest)
        if not hashes:
            _fail(f"{label} pin lacks artifact SHA-256 at line {line_number}: {name}")
        if name in pins:
            _fail(f"{label} contains duplicate package pin: {name}")
        pins[name] = (version, tuple(hashes))
    if not pins:
        _fail(f"{label} has no package pins")
    return pins


def _project_table(root: Path) -> dict[str, object]:
    data = tomllib.loads(_read(root / "pyproject.toml"))
    project = data.get("project")
    if not isinstance(project, dict):
        _fail("pyproject.toml lacks [project]")
    return data


def _project_runtime_pins(root: Path) -> dict[str, str]:
    data = _project_table(root)
    project = data["project"]
    assert isinstance(project, dict)
    requirements = project.get("dependencies", [])
    if not isinstance(requirements, list):
        _fail("project.dependencies must be a list")
    pins: dict[str, str] = {}
    for requirement in requirements:
        name, version = _parse_pin(requirement, "project.dependencies")
        if name in pins:
            _fail(f"project.dependencies contains duplicate package pin: {name}")
        pins[name] = version
    if not pins:
        _fail("project.dependencies must contain at least one reviewed runtime pin")
    return pins


def _project_declared_pins(root: Path) -> dict[str, str]:
    data = _project_table(root)
    project = data["project"]
    assert isinstance(project, dict)
    optional = project.get("optional-dependencies", {})
    if not isinstance(optional, dict):
        _fail("project.optional-dependencies must be a table")
    build_system = data.get("build-system")
    if not isinstance(build_system, dict):
        _fail("pyproject.toml lacks [build-system]")

    sections: tuple[tuple[str, object], ...] = (
        ("project.dependencies", project.get("dependencies", [])),
        ("project.optional-dependencies.dev", optional.get("dev", [])),
        ("build-system.requires", build_system.get("requires", [])),
    )
    pins: dict[str, str] = {}
    for label, requirements in sections:
        if not isinstance(requirements, list):
            _fail(f"{label} must be a list")
        for requirement in requirements:
            name, version = _parse_pin(requirement, label)
            previous = pins.get(name)
            if previous is not None and previous != version:
                _fail(
                    f"pyproject declares conflicting versions for {name}: "
                    f"{previous} vs {version}"
                )
            pins[name] = version
    if not pins:
        _fail("pyproject declares no reviewed dependency pins")
    return pins


def _check_manifest_consistency(root: Path) -> None:
    direct = _parse_pin_file(
        root / "requirements" / "ci-direct.txt",
        "CI direct pins",
    )
    declared = _project_declared_pins(root)
    expected_names = set(declared) | set(MAINTENANCE_ONLY_DIRECT)
    direct_names = set(direct)
    if direct_names != expected_names:
        missing = sorted(expected_names - direct_names)
        extra = sorted(direct_names - expected_names)
        _fail(
            "CI direct/package manifest set drift; "
            f"missing={missing}, unexpected={extra}"
        )
    for name, version in declared.items():
        if direct[name] != version:
            _fail(
                f"CI direct pin must match pyproject exactly for {name}: "
                f"{direct[name]} != {version}"
            )


def _check_action_runtime_lock(root: Path) -> None:
    runtime = _project_runtime_pins(root)
    action_lock = _parse_hashed_lock(
        root / "requirements" / "action-runtime-lock.txt",
        "Action runtime lock",
    )
    ci_lock = _parse_hashed_lock(
        root / "requirements" / "ci-lock.txt",
        "CI dependency lock",
    )

    if set(action_lock) != set(runtime):
        _fail(
            "Action runtime lock package set must exactly match project runtime dependencies; "
            f"expected={sorted(runtime)}, got={sorted(action_lock)}"
        )

    for name, version in runtime.items():
        locked_version, action_hashes = action_lock[name]
        if locked_version != version:
            _fail(
                f"Action runtime lock version must match pyproject for {name}: "
                f"{locked_version} != {version}"
            )
        ci_entry = ci_lock.get(name)
        if ci_entry is None or ci_entry[0] != version:
            _fail(f"CI dependency lock must contain Action runtime pin {name}=={version}")
        if set(action_hashes) != set(ci_entry[1]):
            _fail(f"Action runtime lock hashes must match reviewed CI lock hashes for {name}")


def _ecosystem_block(text: str, ecosystem: str) -> str:
    marker = f'  - package-ecosystem: "{ecosystem}"'
    if text.count(marker) != 1:
        _fail(f"Dependabot must define exactly one {ecosystem!r} update block")
    start = text.index(marker)
    tail = text[start + len(marker) :]
    next_block = tail.find("\n  - package-ecosystem:")
    if next_block >= 0:
        tail = tail[:next_block]
    return marker + tail


def _require_fragments(text: str, fragments: tuple[str, ...], label: str) -> None:
    for fragment in fragments:
        if fragment not in text:
            _fail(f"{label} missing required control: {fragment}")


def _check_dependabot_policy(root: Path) -> None:
    text = _read(root / ".github" / "dependabot.yml")
    if not text.startswith("version: 2\n"):
        _fail("Dependabot configuration must use version: 2")
    for forbidden in (
        "target-branch:",
        "registries:",
        "insecure-external-code-execution:",
    ):
        if forbidden in text:
            _fail(f"Dependabot configuration expands an unreviewed trust boundary: {forbidden}")

    pip_block = _ecosystem_block(text, "pip")
    _require_fragments(
        pip_block,
        (
            'directory: "/"',
            'interval: "weekly"',
            "open-pull-requests-limit: 0",
            '- "dependencies"',
        ),
        "Dependabot pip policy",
    )

    actions_block = _ecosystem_block(text, "github-actions")
    _require_fragments(
        actions_block,
        (
            'directory: "/"',
            'interval: "weekly"',
            "open-pull-requests-limit: 3",
            "cooldown:",
            "default-days: 7",
            'dependency-name: "actions/checkout"',
            'dependency-name: "actions/setup-python"',
            'dependency-name: "actions/attest"',
            'dependency-name: "github/codeql-action"',
            '- "dependencies"',
        ),
        "Dependabot GitHub Actions policy",
    )


def _action_definition_files(root: Path) -> list[Path]:
    workflow_dir = root / ".github" / "workflows"
    workflows = sorted(workflow_dir.glob("*.y*ml"))
    if not workflows:
        _fail("no GitHub Actions workflows found")
    action = root / "action.yml"
    if not action.is_file():
        _fail("root composite action.yml is missing")
    return [*workflows, action]


def _check_action_suppliers(root: Path) -> None:
    for definition in _action_definition_files(root):
        text = _read(definition)
        for reference in USES_RE.findall(text):
            if reference.startswith("./"):
                continue
            if "@" not in reference:
                _fail(f"Action reference missing immutable ref in {definition.name}: {reference}")
            action, ref = reference.rsplit("@", 1)
            normalized = action.lower()
            if normalized not in ALLOWED_ACTIONS:
                _fail(
                    "Action definition introduces an unreviewed Action supplier in "
                    f"{definition.name}: {action}"
                )
            if not SHA_RE.fullmatch(ref):
                _fail(
                    "Action must be pinned to a full commit SHA in "
                    f"{definition.name}: {action}@{ref}"
                )


def _check_workflow_integration(root: Path) -> None:
    project_state = _read(root / ".github" / "workflows" / "project-state.yml")
    _require_fragments(
        project_state,
        (
            "Verify dependency-update integrity",
            "github.actor == 'dependabot[bot]'",
            "github.event.pull_request.base.sha",
            "github.event.pull_request.head.sha",
            "../agentcapdiff-trusted-base/scripts/check_dependency_update_integrity.py",
            "scripts/check_dependency_update_integrity.py",
            '--base-sha "$BASE_SHA"',
            '--head-sha "$HEAD_SHA"',
        ),
        "project-state dependency-update gate",
    )

    release_integrity = _read(
        root / ".github" / "workflows" / "release-integrity.yml"
    )
    _require_fragments(
        release_integrity,
        (
            "Verify dependency-update integrity",
            "../agentcapdiff-trusted-base/scripts/check_dependency_update_integrity.py",
            "scripts/check_dependency_update_integrity.py",
        ),
        "release-integrity dependency-update gate",
    )

    ci = _read(root / ".github" / "workflows" / "ci.yml")
    if "python scripts/check_dependency_update_integrity.py --root ." not in ci:
        _fail("CI must execute the dependency-update regression gate")

    release = _read(root / ".github" / "workflows" / "release.yml")
    if "python scripts/check_dependency_update_integrity.py --root ." not in release:
        _fail("release validation must execute the dependency-update integrity gate")


def _allowed_dependabot_path(path: str) -> bool:
    if path in DEPENDABOT_EXACT_PATHS:
        return True
    return WORKFLOW_PATH_RE.fullmatch(path) is not None


def check_changed_paths(paths: list[str]) -> None:
    if not paths:
        _fail("Dependabot pull request has no changed paths")
    for path in paths:
        if not path or path.startswith("/") or "\x00" in path:
            _fail(f"invalid changed path from git: {path!r}")
        if not _allowed_dependabot_path(path):
            _fail(f"Dependabot pull request changed forbidden path: {path}")


def _git_changed_paths(root: Path, base_sha: str, head_sha: str) -> list[str]:
    for label, value in (("base", base_sha), ("head", head_sha)):
        if not SHA_RE.fullmatch(value):
            _fail(f"invalid {label} SHA for Dependabot diff: {value!r}")
    result = subprocess.run(
        ["git", "diff", "--name-only", "-z", base_sha, head_sha, "--"],
        cwd=root,
        capture_output=True,
        check=False,
        timeout=20,
    )
    if result.returncode != 0:
        stderr = result.stderr[:4096].decode("utf-8", errors="replace")
        _fail(f"git diff failed while bounding Dependabot update surface: {stderr}")
    if len(result.stdout) > MAX_GIT_DIFF_BYTES:
        _fail("Dependabot changed-path output exceeds safety bound")
    try:
        decoded = result.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _fail("Dependabot changed-path output is not valid UTF-8")
    paths = [item for item in decoded.split("\x00") if item]
    check_changed_paths(paths)
    return paths


def check(
    root: Path,
    *,
    base_sha: str | None = None,
    head_sha: str | None = None,
) -> None:
    root = root.resolve()
    _check_manifest_consistency(root)
    _check_action_runtime_lock(root)
    _check_dependabot_policy(root)
    _check_action_suppliers(root)
    _check_workflow_integration(root)
    _read(root / "docs" / "dependency-maintenance.md")

    if (base_sha is None) != (head_sha is None):
        _fail("Dependabot changed-path check requires both base and head SHA")
    if base_sha is not None and head_sha is not None:
        _git_changed_paths(root, base_sha, head_sha)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify dependency/update automation and Dependabot trust boundaries."
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--base-sha")
    parser.add_argument("--head-sha")
    args = parser.parse_args(argv)
    try:
        check(args.root, base_sha=args.base_sha, head_sha=args.head_sha)
    except (
        OSError,
        ValueError,
        subprocess.SubprocessError,
        tomllib.TOMLDecodeError,
    ) as exc:
        print(f"dependency-update-integrity: FAIL: {exc}", file=sys.stderr)
        return 1
    print("dependency-update-integrity: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
