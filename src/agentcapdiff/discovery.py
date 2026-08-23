from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .models import ToolRecord

SUPPORTED_SUFFIXES = {".json", ".yaml", ".yml"}
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", ".tox"}


class DiscoveryLimitError(ValueError):
    """Raised when untrusted discovery input exceeds a configured safety bound."""


@dataclass(frozen=True)
class DiscoveryLimits:
    max_file_bytes: int = 1_048_576
    max_total_bytes: int = 8_388_608
    max_documents: int = 1_000
    max_depth: int = 64
    max_nodes_per_document: int = 100_000


DEFAULT_LIMITS = DiscoveryLimits()


def _read(path: Path, limits: DiscoveryLimits) -> tuple[Any, int]:
    if path.is_symlink():
        raise DiscoveryLimitError(f"refusing to read symlinked input: {path}")
    size = path.stat().st_size
    if size > limits.max_file_bytes:
        raise DiscoveryLimitError(
            f"input file exceeds {limits.max_file_bytes} byte limit: {path} ({size} bytes)"
        )
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text), size
    return yaml.safe_load(text), size


def _tool_from_mapping(item: dict[str, Any], source: str) -> ToolRecord | None:
    # OpenAI-style: {"type":"function", "function":{"name":...,"description":...}}
    fn = item.get("function")
    if isinstance(fn, dict) and isinstance(fn.get("name"), str):
        schema = fn.get("parameters")
        return ToolRecord(
            str(fn["name"]),
            str(fn.get("description", "")),
            source,
            schema if isinstance(schema, dict) else None,
            "openai",
        )

    # MCP tool object: {"name":..., "description":..., "inputSchema":...}
    if isinstance(item.get("name"), str) and (
        "inputSchema" in item or "input_schema" in item
    ):
        schema = item.get("inputSchema", item.get("input_schema"))
        return ToolRecord(
            str(item["name"]),
            str(item.get("description", "")),
            source,
            schema if isinstance(schema, dict) else None,
            "mcp",
        )

    # Generic nested tool object. Keep it explicit rather than pretending it is MCP.
    if isinstance(item.get("name"), str) and item.get("type") == "tool":
        return ToolRecord(
            str(item["name"]),
            str(item.get("description", "")),
            source,
            None,
            "generic",
        )
    return None


def _walk(value: Any, source: str, out: list[ToolRecord], limits: DiscoveryLimits) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    visited: set[int] = set()
    nodes = 0

    while stack:
        current, depth = stack.pop()
        if depth > limits.max_depth:
            raise DiscoveryLimitError(
                f"input nesting exceeds depth limit {limits.max_depth}: {source}"
            )

        if not isinstance(current, (dict, list)):
            continue

        object_id = id(current)
        if object_id in visited:
            continue
        visited.add(object_id)

        nodes += 1
        if nodes > limits.max_nodes_per_document:
            raise DiscoveryLimitError(
                "input structure exceeds node limit "
                f"{limits.max_nodes_per_document}: {source}"
            )

        if isinstance(current, dict):
            direct = _tool_from_mapping(current, source)
            if direct:
                out.append(direct)
            for child in current.values():
                if isinstance(child, (dict, list)):
                    stack.append((child, depth + 1))
        else:
            for child in current:
                if isinstance(child, (dict, list)):
                    stack.append((child, depth + 1))


def discover_tools(
    root: Path,
    limits: DiscoveryLimits = DEFAULT_LIMITS,
) -> list[ToolRecord]:
    if not root.exists():
        raise FileNotFoundError(f"scan path does not exist: {root}")

    candidates = (root,) if root.is_file() else (p for p in root.rglob("*") if p.is_file())
    found: list[ToolRecord] = []
    total_bytes = 0
    documents = 0

    for path in candidates:
        if path.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue

        documents += 1
        if documents > limits.max_documents:
            raise DiscoveryLimitError(
                f"candidate document count exceeds limit {limits.max_documents}: {root}"
            )

        try:
            data, size = _read(path, limits)
        except (OSError, UnicodeError, json.JSONDecodeError, yaml.YAMLError):
            # Malformed/unreadable documents are ignored; resource-limit violations are not.
            continue

        total_bytes += size
        if total_bytes > limits.max_total_bytes:
            raise DiscoveryLimitError(
                f"total parsed input exceeds {limits.max_total_bytes} byte limit: {root}"
            )

        _walk(data, str(path), found, limits)

    dedup: dict[tuple[str, str], ToolRecord] = {}
    for tool in found:
        dedup[(tool.name, tool.source)] = tool
    return sorted(dedup.values(), key=lambda x: (x.name.lower(), x.source))
