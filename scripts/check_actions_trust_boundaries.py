from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


class ActionsTrustBoundaryError(ValueError):
    """Raised when a workflow weakens the reviewed GitHub Actions trust boundary."""


LOCK_INSTALL = (
    "python -m pip --isolated --disable-pip-version-check install --require-hashes "
    "--no-deps --no-cache-dir --only-binary=:all: "
    "--index-url=https://pypi.org/simple -r requirements/ci-lock.txt"
)
PACKAGE_INSTALL = "python -m pip install . --no-deps --no-build-isolation"
TRUSTED_BASE = "../agentcapdiff-trusted-base"
WRITE_PERMISSION_RE = re.compile(r"^\s+[A-Za-z0-9_-]+:\s*write\s*$", re.MULTILINE)


def _fail(message: str) -> None:
    raise ActionsTrustBoundaryError(message)


def _read(path: Path) -> str:
    if not path.is_file():
        _fail(f"required workflow missing: {path.as_posix()}")
    return path.read_text(encoding="utf-8")


def _require(text: str, fragments: tuple[str, ...], label: str) -> None:
    for fragment in fragments:
        if fragment not in text:
            _fail(f"{label} missing required trust-boundary control: {fragment}")


def _step_block(text: str, name: str) -> str:
    marker = f"      - name: {name}"
    start = text.find(marker)
    if start < 0:
        _fail(f"workflow missing required step: {name}")
    tail = text[start + len(marker) :]
    next_step = tail.find("\n      - ")
    end = next_step if next_step >= 0 else len(tail)
    return marker + tail[:end]


def _check_global_event_and_side_channels(workflow: Path, text: str) -> None:
    forbidden_triggers = ("pull_request_target:", "workflow_run:")
    for trigger in forbidden_triggers:
        if trigger in text:
            _fail(f"privilege-crossing trigger is forbidden in {workflow.name}: {trigger}")

    for fragment in (
        "actions/cache@",
        "actions/upload-artifact@",
        "actions/download-artifact@",
    ):
        if fragment in text:
            _fail(f"cross-job cache/artifact side channel is forbidden in {workflow.name}: {fragment}")

    for expression in (
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.label",
    ):
        if expression in text:
            _fail(
                f"untrusted pull-request metadata must not enter workflow commands: "
                f"{workflow.name}: {expression}"
            )

    if "pull_request:" in text and WRITE_PERMISSION_RE.search(text):
        for channel in ("GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT"):
            if channel in text:
                _fail(
                    f"write-capable pull-request workflow must not use mutable file-command "
                    f"channel {channel}: {workflow.name}"
                )


def _check_trusted_static_workflow(path: Path, *, sarif_upload: bool) -> None:
    text = _read(path)
    label = path.name
    _require(
        text,
        (
            "pull_request:",
            "fetch-depth: 0",
            "persist-credentials: false",
            "BASE_SHA: ${{ github.event.pull_request.base.sha }}",
            'git worktree add --detach ../agentcapdiff-trusted-base "$BASE_SHA"',
            f"working-directory: {TRUSTED_BASE}",
            LOCK_INSTALL,
            PACKAGE_INSTALL,
        ),
        label,
    )

    if text.count(PACKAGE_INSTALL) != 1:
        _fail(f"{label} must install exactly one package source: the trusted base")

    for step_name in (
        "Verify trusted base runner provenance",
        "Install trusted base CI dependencies",
        "Install trusted base package",
    ):
        block = _step_block(text, step_name)
        if f"working-directory: {TRUSTED_BASE}" not in block:
            _fail(f"{label} step must execute from trusted base: {step_name}")

    install_block = _step_block(text, "Install trusted base package")
    if PACKAGE_INSTALL not in install_block:
        _fail(f"{label} package install escaped trusted-base step")

    for forbidden in (
        "run: python scripts/",
        "run: python3 scripts/",
        "pytest ",
        "ruff check",
    ):
        if forbidden in text:
            _fail(f"static PR workflow executes candidate code: {label}: {forbidden}")

    for channel in ("GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT"):
        if channel in text:
            _fail(f"static PR workflow uses mutable file-command channel: {label}: {channel}")

    if sarif_upload:
        _require(
            text,
            (
                "security-events: write",
                "github.event.pull_request.head.repo.full_name == github.repository",
            ),
            label,
        )


def _check_codeql(path: Path) -> None:
    text = _read(path)
    block = _step_block(text, "Verify runner provenance from trusted source")
    _require(
        block,
        (
            "EVENT_NAME: ${{ github.event_name }}",
            "BASE_SHA: ${{ github.event.pull_request.base.sha }}",
            'if [[ "$EVENT_NAME" == "pull_request" ]]; then',
            'git worktree add --detach ../agentcapdiff-trusted-base "$BASE_SHA"',
            'python3 "../agentcapdiff-trusted-base/$CHECKER" "${ARGS[@]}"',
            'python3 "$CHECKER" "${ARGS[@]}"',
        ),
        path.name,
    )
    if "run: python3 scripts/check_ci_environment.py" in text:
        _fail("CodeQL must not execute the pull-request copy of the provenance checker")


def _check_read_only_candidate_execution(path: Path) -> None:
    text = _read(path)
    if "pull_request:" not in text:
        _fail(f"expected pull_request trigger: {path.name}")
    if WRITE_PERMISSION_RE.search(text):
        _fail(f"candidate-code execution workflow must remain read-only: {path.name}")
    for fragment in ("secrets.", "GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT"):
        if fragment in text:
            _fail(f"read-only candidate workflow exposes mutable/secret channel: {path.name}: {fragment}")


def _check_trusted_integrity_gate(path: Path, checker_names: tuple[str, ...]) -> None:
    text = _read(path)
    _require(
        text,
        (
            "pull_request:",
            "fetch-depth: 0",
            "BASE_SHA: ${{ github.event.pull_request.base.sha }}",
            'git worktree add --detach ../agentcapdiff-trusted-base "$BASE_SHA"',
            "EVENT_NAME: ${{ github.event_name }}",
            'if [[ "$EVENT_NAME" == "pull_request" ]]; then',
            'GITHUB_WORKSPACE',
        ),
        path.name,
    )
    for checker in checker_names:
        trusted = f'../agentcapdiff-trusted-base/scripts/{checker}'
        candidate = f'scripts/{checker}'
        if trusted not in text or candidate not in text:
            _fail(f"{path.name} must select trusted-base/current checker for {checker}")


def check(root: Path) -> None:
    root = root.resolve()
    workflow_dir = root / ".github" / "workflows"
    workflows = sorted(workflow_dir.glob("*.y*ml"))
    if not workflows:
        _fail("no GitHub Actions workflows found")

    for workflow in workflows:
        _check_global_event_and_side_channels(workflow, _read(workflow))

    _check_trusted_static_workflow(workflow_dir / "agentcapdiff.yml", sarif_upload=True)
    _check_trusted_static_workflow(workflow_dir / "pr-capability-diff.yml", sarif_upload=False)
    _check_codeql(workflow_dir / "codeql.yml")
    _check_read_only_candidate_execution(workflow_dir / "ci.yml")
    _check_trusted_integrity_gate(
        workflow_dir / "project-state.yml",
        ("check_release_integrity.py", "check_actions_trust_boundaries.py"),
    )
    _check_trusted_integrity_gate(
        workflow_dir / "release-integrity.yml",
        (
            "check_release_integrity.py",
            "check_attestation_integrity.py",
            "check_release_transaction_integrity.py",
            "check_actions_trust_boundaries.py",
        ),
    )

    release = _read(workflow_dir / "release.yml")
    _require(release, ("permissions: {}", "push:", "tags:", "contents: write", "id-token: write"), "release.yml")
    if "pull_request:" in release:
        _fail("release workflow must never be reachable from pull_request")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify GitHub Actions event, permission, and PR trust boundaries."
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    try:
        check(args.root)
    except (OSError, UnicodeDecodeError, ActionsTrustBoundaryError) as exc:
        print(f"actions-trust-boundaries: FAIL: {exc}", file=sys.stderr)
        return 1
    print("actions-trust-boundaries: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
