from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
MAX_INPUT_BYTES = 8 * 1024 * 1024


class ReleaseStateError(ValueError):
    """Raised when remote release state is malformed or ambiguous."""


def _read_stdin_json() -> Any:
    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise ReleaseStateError(f"release state JSON exceeds {MAX_INPUT_BYTES} bytes")
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseStateError("release state must be valid UTF-8 JSON") from exc


def _require_tag(tag: str) -> None:
    if not tag or "\n" in tag or "\r" in tag:
        raise ReleaseStateError("release tag must be a non-empty single line")


def _require_source_sha(source_sha: str) -> None:
    if SHA_RE.fullmatch(source_sha) is None:
        raise ReleaseStateError("source SHA must be an exact 40-character lowercase Git commit")


def release_presence(payload: Any, tag: str) -> str:
    _require_tag(tag)
    if not isinstance(payload, list):
        raise ReleaseStateError("release list payload must be a JSON array")
    matches = 0
    for item in payload:
        if not isinstance(item, dict):
            raise ReleaseStateError("release list entry must be an object")
        tag_name = item.get("tagName")
        if not isinstance(tag_name, str):
            raise ReleaseStateError("release list tagName must be a string")
        if tag_name == tag:
            matches += 1
    if matches > 1:
        raise ReleaseStateError(f"multiple releases unexpectedly reference tag {tag!r}")
    return "present" if matches == 1 else "missing"


def ownership_marker(source_sha: str) -> str:
    _require_source_sha(source_sha)
    return f"<!-- agentcapdiff-release-source:{source_sha} -->"


def classify_release(payload: Any, tag: str, source_sha: str) -> str:
    _require_tag(tag)
    marker = ownership_marker(source_sha)
    if not isinstance(payload, dict):
        raise ReleaseStateError("release view payload must be a JSON object")

    tag_name = payload.get("tagName")
    is_draft = payload.get("isDraft")
    is_immutable = payload.get("isImmutable")
    body = payload.get("body")
    if tag_name != tag:
        raise ReleaseStateError(
            f"release view tag mismatch: expected={tag!r}, got={tag_name!r}"
        )
    if not isinstance(is_draft, bool) or not isinstance(is_immutable, bool):
        raise ReleaseStateError("release draft/immutable fields must be booleans")
    if body is None:
        body = ""
    if not isinstance(body, str):
        raise ReleaseStateError("release body must be a string or null")
    if is_draft and is_immutable:
        raise ReleaseStateError("release cannot be both draft and immutable")

    owned = marker in body
    ownership = "owned" if owned else "unowned"
    if is_immutable:
        state = "immutable"
    elif is_draft:
        state = "draft"
    else:
        state = "mutable"
    return f"{state}-{ownership}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Classify GitHub release state for fail-closed retry handling."
    )
    parser.add_argument("--mode", choices=("exists", "classify"), required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-sha")
    args = parser.parse_args(argv)

    try:
        payload = _read_stdin_json()
        if args.mode == "exists":
            result = release_presence(payload, args.tag)
        else:
            if args.source_sha is None:
                raise ReleaseStateError("--source-sha is required for classify mode")
            result = classify_release(payload, args.tag, args.source_sha)
    except ReleaseStateError as exc:
        print(f"release-state: FAIL: {exc}", file=sys.stderr)
        return 1

    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
