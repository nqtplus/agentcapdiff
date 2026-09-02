from __future__ import annotations

from collections.abc import Hashable
from typing import Any

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode

_MERGE_TAG = "tag:yaml.org,2002:merge"
_MERGE_KEY = ("__agentcapdiff_yaml_merge__",)


class UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate raw mapping keys.

    Duplicate detection runs before PyYAML flattens YAML merge keys. This preserves
    the existing `<<` merge behavior, including an explicit local key overriding a
    merged value, while rejecting two raw definitions of the same key in one mapping.
    """

    def construct_mapping(self, node: MappingNode, deep: bool = False) -> dict[Any, Any]:
        if isinstance(node, MappingNode):
            seen: set[Hashable] = set()
            for key_node, _ in node.value:
                if key_node.tag == _MERGE_TAG:
                    key: Any = _MERGE_KEY
                else:
                    key = self.construct_object(key_node, deep=deep)
                if not isinstance(key, Hashable):
                    # The parent SafeLoader will produce the normal unhashable-key error.
                    continue
                if key in seen:
                    raise ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        f"found duplicate mapping key {key!r}",
                        key_node.start_mark,
                    )
                seen.add(key)
        return super().construct_mapping(node, deep=deep)


def safe_load_unique(text: str) -> Any:
    """Parse YAML safely while rejecting duplicate mapping keys at every depth."""

    return yaml.load(text, Loader=UniqueKeySafeLoader)
