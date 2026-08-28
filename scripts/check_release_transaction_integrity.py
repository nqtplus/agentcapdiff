from __future__ import annotations

import argparse
import sys
from pathlib import Path


class ReleaseTransactionIntegrityError(ValueError):
    """Raised when release retry/cleanup/race controls are weakened."""


def _read(path: Path) -> str:
    if not path.is_file():
        raise ReleaseTransactionIntegrityError(
            f"required release-transaction file missing: {path.as_posix()}"
        )
    return path.read_text(encoding="utf-8")


def _step_block(text: str, name: str) -> str:
    marker = f"      - name: {name}"
    start = text.find(marker)
    if start < 0:
        raise ReleaseTransactionIntegrityError(f"release workflow missing step: {name}")
    tail = text[start + len(marker) :]
    candidates = [
        index
        for token in ("\n      - name:", "\n      - uses:", "\n  ")
        if (index := tail.find(token)) >= 0
    ]
    end = min(candidates) if candidates else len(tail)
    return marker + tail[:end]


def _require_fragments(text: str, fragments: tuple[str, ...], label: str) -> None:
    for fragment in fragments:
        if fragment not in text:
            raise ReleaseTransactionIntegrityError(
                f"{label} missing required control: {fragment}"
            )


def _require_guard(text: str, step_name: str) -> None:
    block = _step_block(text, step_name)
    guard = "if: steps.release_state.outputs.already_published != 'true'"
    if guard not in block:
        raise ReleaseTransactionIntegrityError(
            f"release mutation step must be idempotency-guarded: {step_name}"
        )


def check(root: Path) -> None:
    release = _read(root / ".github" / "workflows" / "release.yml")
    helper = _read(root / "scripts" / "release_transaction_state.py")

    _require_fragments(
        release,
        (
            "concurrency:",
            "group: release-${{ github.ref }}",
            "cancel-in-progress: false",
            "id: release_state",
            'gh release list --limit 1000 --json tagName',
            'python scripts/release_transaction_state.py \\\n                --mode exists \\\n                --tag "$GITHUB_REF_NAME"',
            'python scripts/release_transaction_state.py \\\n                --mode classify \\\n                --tag "$GITHUB_REF_NAME" \\\n                --source-sha "$GITHUB_SHA"',
            "immutable-owned)",
            "draft-owned|mutable-owned)",
            'echo "already_published=true" >> "$GITHUB_OUTPUT"',
            'gh release delete "$GITHUB_REF_NAME" --yes',
            "id: create_release",
            "id: publish_release",
            "id: cleanup_release",
            '<!-- agentcapdiff-release-source:${GITHUB_SHA} -->',
        ),
        "release workflow",
    )
    if "cancel-in-progress: true" in release:
        raise ReleaseTransactionIntegrityError(
            "same-tag release runs must serialize rather than cancel an active publisher"
        )
    if "--cleanup-tag" in release:
        raise ReleaseTransactionIntegrityError(
            "release failure cleanup must preserve the source tag for safe retry"
        )
    if release.count('gh release delete "$GITHUB_REF_NAME" --yes') != 2:
        raise ReleaseTransactionIntegrityError(
            "release deletion must occur only in state reconciliation and failure cleanup"
        )

    critical_steps = (
        "Reset release artifact directories",
        "Build reviewed source and wheel artifacts",
        "Generate validated SPDX SBOM and checksums",
        "Attest build provenance from validated checksums",
        "Attest SPDX SBOM from validated checksums",
        "Verify signed subject, source, signer, and SBOM binding",
        "Create draft release with exact validated assets",
        "Publish and require GitHub immutable release protection",
    )
    for step_name in critical_steps:
        _require_guard(release, step_name)

    create = _step_block(release, "Create draft release with exact validated assets")
    _require_fragments(
        create,
        (
            "id: create_release",
            "--draft",
            "--verify-tag",
            '--notes "<!-- agentcapdiff-release-source:${GITHUB_SHA} -->"',
        ),
        "draft release creation",
    )

    publish = _step_block(
        release,
        "Publish and require GitHub immutable release protection",
    )
    _require_fragments(
        publish,
        (
            "id: publish_release",
            'gh release edit "$GITHUB_REF_NAME" --draft=false',
            '--json isImmutable --jq .isImmutable',
            'if [[ "$immutable" != "true" ]]; then',
            "exit 1",
        ),
        "release publication",
    )
    if "gh release delete" in publish:
        raise ReleaseTransactionIntegrityError(
            "publication step must not delete release/tag before cleanup reclassifies state"
        )

    cleanup = _step_block(release, "Cleanup partial release while preserving source tag")
    _require_fragments(
        cleanup,
        (
            "id: cleanup_release",
            "always()",
            "steps.create_release.outcome == 'success'",
            "steps.publish_release.outcome != 'success'",
            "draft-owned|mutable-owned)",
            "immutable-owned)",
            'gh release delete "$GITHUB_REF_NAME" --yes',
        ),
        "release failure cleanup",
    )

    create_index = release.find("id: create_release")
    publish_index = release.find("id: publish_release")
    cleanup_index = release.find("id: cleanup_release")
    if not (0 <= create_index < publish_index < cleanup_index):
        raise ReleaseTransactionIntegrityError(
            "release transaction order must be create -> publish -> cleanup"
        )

    _require_fragments(
        helper,
        (
            "MAX_INPUT_BYTES",
            "def release_presence(",
            "def ownership_marker(",
            "def classify_release(",
            'return f"<!-- agentcapdiff-release-source:{source_sha} -->"',
            'return f"{state}-{ownership}"',
            'choices=("exists", "classify")',
        ),
        "release state classifier",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify AgentCapDiff release retry/idempotency transaction controls."
    )
    parser.add_argument("--root", type=Path, default=Path("."))
    args = parser.parse_args(argv)
    try:
        check(args.root.resolve())
    except (OSError, UnicodeDecodeError, ReleaseTransactionIntegrityError) as exc:
        print(f"release-transaction-integrity: FAIL: {exc}", file=sys.stderr)
        return 1
    print("release-transaction-integrity: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
