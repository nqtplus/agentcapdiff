from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any


class DuplicateJSONObjectKeyError(ValueError):
    """Raised when a JSON object defines the same decoded key more than once."""


def _unique_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONObjectKeyError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def loads_unique(
    text: str,
    *,
    parse_constant: Callable[[str], Any] | None = None,
) -> Any:
    """Parse JSON while rejecting duplicate object keys at every nesting depth."""

    kwargs: dict[str, Any] = {"object_pairs_hook": _unique_object_pairs}
    if parse_constant is not None:
        kwargs["parse_constant"] = parse_constant
    return json.loads(text, **kwargs)
