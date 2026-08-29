from __future__ import annotations

import json
from collections.abc import Iterator
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
    max_entries: int = 50_000


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
    try:
        if path.suffix.lower() == ".json":
            return json.loads(text), size
        return yaml.safe_load(text), size
    except RecursionError as exc:
        raise DiscoveryLimitError(f"input parser recursion exceeds safety limit: {path}") from exc


def _schema(item: dict[str, Any], key: str) -> dict[str, Any] | None:
    value = item.get(key)
    return value if isinstance(value, dict) else None


def _framework_hint(item: dict[str, Any]) -> str:
    """Return only explicit/static framework hints; never import target framework code."""
    values: list[str] = []
    for key in ("framework", "adapter", "provider", "library", "class_name", "__class__"):
        value = item.get(key)
        if isinstance(value, str):
            values.append(value)
    identifier = item.get("id")
    if isinstance(identifier, str):
        values.append(identifier)
    elif isinstance(identifier, list):
        values.extend(str(part) for part in identifier if isinstance(part, (str, int)))
    return " ".join(values).lower()


def _tool_from_mapping(item: dict[str, Any], source: str) -> ToolRecord | None:
    # OpenAI API-style: {"type":"function", "function":{"name":..., "parameters":...}}
    fn = item.get("function")
    if isinstance(fn, dict) and isinstance(fn.get("name"), str):
        schema = _schema(fn, "parameters")
        return ToolRecord(
            str(fn["name"]),
            str(fn.get("description", "")),
            source,
            schema,
            "openai",
        )

    name = item.get("name")
    if not isinstance(name, str):
        return None
    description = str(item.get("description", ""))

    # OpenAI Agents SDK FunctionTool exposes params_json_schema as a static JSON schema.
    params_json_schema = _schema(item, "params_json_schema")
    if params_json_schema is not None:
        return ToolRecord(name, description, source, params_json_schema, "openai-agents")

    # OpenAI Responses/API direct function-tool shape.
    parameters = _schema(item, "parameters")
    if item.get("type") == "function" and parameters is not None:
        return ToolRecord(name, description, source, parameters, "openai")

    # MCP Tool uses camel-case inputSchema.
    input_schema_mcp = _schema(item, "inputSchema")
    if input_schema_mcp is not None:
        return ToolRecord(name, description, source, input_schema_mcp, "mcp")

    # Claude client-tool definitions use snake-case input_schema.
    input_schema_claude = _schema(item, "input_schema")
    if input_schema_claude is not None:
        return ToolRecord(name, description, source, input_schema_claude, "claude")

    hint = _framework_hint(item)
    args_schema = _schema(item, "args_schema")
    tool_call_schema = _schema(item, "tool_call_schema")

    # CrewAI BaseTool-style serialized metadata. result_as_answer is CrewAI-specific
    # evidence; an explicit framework hint is also accepted when present in static data.
    if args_schema is not None and ("crewai" in hint or "result_as_answer" in item):
        return ToolRecord(name, description, source, args_schema, "crewai")

    # LangChain BaseTool / LangGraph tool-compatible metadata. LangGraph commonly consumes
    # LangChain-compatible tools; explicit provenance is retained when statically supplied.
    if tool_call_schema is not None:
        adapter = "langgraph" if "langgraph" in hint else "langchain"
        return ToolRecord(name, description, source, tool_call_schema, adapter)
    if args_schema is not None and (
        "langchain" in hint
        or "langgraph" in hint
        or "return_direct" in item
        or "response_format" in item
    ):
        adapter = "langgraph" if "langgraph" in hint else "langchain"
        return ToolRecord(name, description, source, args_schema, adapter)

    # Ambiguous args_schema still carries useful static schema evidence, but framework
    # attribution is deliberately generic rather than guessed.
    if args_schema is not None:
        return ToolRecord(name, description, source, args_schema, "generic")

    # Generic nested tool object. Keep it explicit rather than pretending it is a framework.
    if item.get("type") == "tool":
        return ToolRecord(name, description, source, None, "generic")
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


def _candidate_files(root: Path, limits: DiscoveryLimits) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        raise DiscoveryLimitError(f"scan path must be a regular file or directory: {root}")

    for entries, path in enumerate(root.rglob("*"), start=1):
        if entries > limits.max_entries:
            raise DiscoveryLimitError(
                f"filesystem entry traversal exceeds limit {limits.max_entries}: {root}"
            )
        if path.is_file():
            yield path


def _merge_tool_records(records: list[ToolRecord]) -> ToolRecord:
    if len(records) == 1:
        return records[0]

    descriptions = sorted({record.description for record in records if record.description})
    adapters = {record.adapter or "generic" for record in records}
    schemas: list[dict[str, Any]] = []
    seen_schema_ids: set[int] = set()
    for record in records:
        schema = record.input_schema
        if schema is None or id(schema) in seen_schema_ids:
            continue
        seen_schema_ids.add(id(schema))
        schemas.append(schema)

    if not schemas:
        merged_schema = None
    elif len(schemas) == 1:
        merged_schema = schemas[0]
    else:
        # Preserve every static schema branch rather than letting traversal order choose a winner.
        # Scope/capability inference already traverses nested schema containers conservatively.
        merged_schema = {"allOf": schemas}

    adapter = next(iter(adapters)) if len(adapters) == 1 else "generic"
    return ToolRecord(
        name=records[0].name,
        description=" | ".join(descriptions),
        source=records[0].source,
        input_schema=merged_schema,
        adapter=adapter,
    )


def discover_tools(
    root: Path,
    limits: DiscoveryLimits = DEFAULT_LIMITS,
) -> list[ToolRecord]:
    if not root.exists():
        raise FileNotFoundError(f"scan path does not exist: {root}")
    if root.is_symlink() and root.is_dir():
        raise DiscoveryLimitError(f"refusing symlinked scan root: {root}")

    root_boundary = root.resolve() if root.is_dir() else root.parent.resolve()
    candidates = _candidate_files(root, limits)
    found: list[ToolRecord] = []
    total_bytes = 0
    documents = 0

    for path in candidates:
        if path.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue

        try:
            path.resolve().relative_to(root_boundary)
        except ValueError as exc:
            raise DiscoveryLimitError(f"scan input escapes root boundary: {path}") from exc

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

    grouped: dict[tuple[str, str], list[ToolRecord]] = {}
    for tool in found:
        grouped.setdefault((tool.name, tool.source), []).append(tool)
    merged = [_merge_tool_records(records) for records in grouped.values()]
    return sorted(merged, key=lambda x: (x.name.lower(), x.source))
