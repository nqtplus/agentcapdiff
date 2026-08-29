from __future__ import annotations

import importlib.metadata
import os
import subprocess
import sys
import tempfile
import tomllib
import venv
from pathlib import Path

SUPPORTED_PYTHON = {(3, 11), (3, 12), (3, 13)}
SUPPORTED_FAIL_ON = {"never", "medium", "high"}


class CompositeActionError(ValueError):
    """Raised when the composite Action runtime contract is unsafe or invalid."""


def _fail(message: str) -> None:
    raise CompositeActionError(message)


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if value is None:
        _fail(f"missing required GitHub Action environment variable: {name}")
    return value


def _inside(base: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(base)
    except ValueError:
        return False
    return True


def _resolve_workspace_path(
    workspace: Path,
    raw: str,
    *,
    label: str,
    require_file: bool = False,
) -> tuple[Path, str]:
    if not raw:
        _fail(f"{label} must not be empty")

    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = workspace / candidate
    if candidate.is_symlink():
        _fail(f"{label} must not be a symlink: {raw!r}")

    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        _fail(f"{label} does not resolve to an existing path: {raw!r}: {exc}")

    if not _inside(workspace, resolved):
        _fail(f"{label} escapes GITHUB_WORKSPACE: {raw!r}")
    if require_file and not resolved.is_file():
        _fail(f"{label} must resolve to a regular file: {raw!r}")
    if not require_file and not (resolved.is_file() or resolved.is_dir()):
        _fail(f"{label} must resolve to a regular file or directory: {raw!r}")

    relative = resolved.relative_to(workspace)
    cli_arg = "." if relative == Path(".") else relative.as_posix()
    return resolved, cli_arg


def validate_inputs(
    workspace: Path,
    scan_raw: str,
    policy_raw: str,
    fail_on: str,
) -> tuple[str, str | None, str]:
    workspace = workspace.resolve(strict=True)
    if not workspace.is_dir():
        _fail("GITHUB_WORKSPACE must resolve to a directory")

    _, scan_arg = _resolve_workspace_path(workspace, scan_raw, label="scan path")

    policy_arg: str | None
    if policy_raw == "":
        policy_arg = None
    else:
        _, policy_arg = _resolve_workspace_path(
            workspace,
            policy_raw,
            label="policy path",
            require_file=True,
        )

    if fail_on not in SUPPORTED_FAIL_ON:
        _fail(
            "fail-on must be one of "
            f"{sorted(SUPPORTED_FAIL_ON)!r}, got {fail_on!r}"
        )
    return scan_arg, policy_arg, fail_on


def _runtime_dependency_versions(root: Path) -> dict[str, str]:
    data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project = data.get("project")
    if not isinstance(project, dict):
        _fail("trusted action source lacks [project] metadata")
    requirements = project.get("dependencies")
    if not isinstance(requirements, list) or not requirements:
        _fail("trusted action source has no runtime dependency pins")

    versions: dict[str, str] = {}
    for requirement in requirements:
        if not isinstance(requirement, str) or requirement.count("==") != 1:
            _fail(f"runtime dependency must be an exact pin: {requirement!r}")
        name, version = requirement.split("==", 1)
        normalized = name.strip().lower().replace("_", "-")
        if not normalized or not version.strip():
            _fail(f"invalid runtime dependency pin: {requirement!r}")
        versions[normalized] = version.strip()
    return versions


def _verify_installed_runtime(root: Path) -> None:
    expected = _runtime_dependency_versions(root)
    for name, version in expected.items():
        try:
            installed = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            _fail(f"locked Action runtime dependency is not installed: {name}=={version}")
        if installed != version:
            _fail(
                "Action runtime dependency version mismatch: "
                f"{name} expected {version}, got {installed}"
            )


def _sanitize_import_path(root: Path, workspace: Path) -> None:
    trusted_src = (root / "src").resolve(strict=True)
    filtered: list[str] = []
    for entry in sys.path:
        if not entry:
            continue
        try:
            resolved = Path(entry).resolve()
        except OSError:
            continue
        if _inside(workspace, resolved):
            continue
        filtered.append(entry)
    sys.path[:] = [str(trusted_src), *filtered]


def _invoke_scan(root: Path, workspace: Path, argv: list[str]) -> int:
    _sanitize_import_path(root, workspace)
    _verify_installed_runtime(root)
    from agentcapdiff.cli import main as cli_main

    return cli_main(argv)


def _venv_python(venv_dir: Path) -> Path:
    return venv_dir / "bin" / "python"


def _install_runtime(venv_python: Path, lock: Path) -> None:
    command = [
        str(venv_python),
        "-I",
        "-m",
        "pip",
        "--isolated",
        "--disable-pip-version-check",
        "install",
        "--require-hashes",
        "--no-deps",
        "--no-cache-dir",
        "--only-binary=:all:",
        "--index-url=https://pypi.org/simple",
        "-r",
        str(lock),
    ]
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        _fail(f"failed to install the hash-locked Action runtime: exit {result.returncode}")


def _bootstrap() -> int:
    if _required_env("GITHUB_ACTIONS") != "true":
        _fail("composite Action wrapper must run inside GitHub Actions")
    if _required_env("RUNNER_OS") != "Linux" or _required_env("RUNNER_ARCH") != "X64":
        _fail("composite Action currently supports only Linux X64 runners")
    if sys.version_info[:2] not in SUPPORTED_PYTHON:
        _fail(
            "composite Action requires CPython 3.11, 3.12, or 3.13; "
            f"got {sys.version_info.major}.{sys.version_info.minor}"
        )

    root = Path(__file__).resolve().parents[1]
    declared_action_path = Path(_required_env("AGENTCAPDIFF_ACTION_PATH")).resolve(strict=True)
    if declared_action_path != root:
        _fail("github.action_path does not match the executing trusted Action source")

    workspace = Path(_required_env("AGENTCAPDIFF_WORKSPACE")).resolve(strict=True)
    scan_arg, policy_arg, fail_on = validate_inputs(
        workspace,
        _required_env("AGENTCAPDIFF_INPUT_PATH"),
        _required_env("AGENTCAPDIFF_INPUT_POLICY"),
        _required_env("AGENTCAPDIFF_INPUT_FAIL_ON"),
    )

    runner_temp = Path(_required_env("RUNNER_TEMP")).resolve(strict=True)
    if not runner_temp.is_dir():
        _fail("RUNNER_TEMP must resolve to a directory")

    lock = root / "requirements" / "action-runtime-lock.txt"
    if not lock.is_file() or lock.is_symlink():
        _fail("trusted Action runtime lock is missing or symlinked")

    with tempfile.TemporaryDirectory(prefix="agentcapdiff-", dir=runner_temp) as tmp:
        venv_dir = Path(tmp) / "venv"
        venv.EnvBuilder(with_pip=True, clear=True).create(venv_dir)
        python = _venv_python(venv_dir)
        if not python.is_file():
            _fail("isolated Action virtual environment did not create a Python executable")
        _install_runtime(python, lock)

        scan_argv = ["scan", scan_arg, "--fail-on", fail_on]
        if policy_arg is not None:
            scan_argv.extend(["--policy", policy_arg])

        command = [
            str(python),
            "-I",
            str(Path(__file__).resolve()),
            "--invoke",
            *scan_argv,
        ]
        result = subprocess.run(command, cwd=workspace, check=False)
        return result.returncode


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if args and args[0] == "--invoke":
            root = Path(__file__).resolve().parents[1]
            workspace = Path(_required_env("AGENTCAPDIFF_WORKSPACE")).resolve(strict=True)
            return _invoke_scan(root, workspace, args[1:])
        return _bootstrap()
    except (
        CompositeActionError,
        OSError,
        RuntimeError,
        subprocess.SubprocessError,
        tomllib.TOMLDecodeError,
    ) as exc:
        print(f"agentcapdiff-action: FAIL: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
