from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .models import ToolRecord

SUPPORTED_SUFFIXES = {".json", ".yaml", ".yml"}
IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", "dist", "build", ".tox"}


def _read(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        return json.loads(text)
    return yaml.safe_load(text)


def _tool_from_mapping(item: dict[str, Any], source: str) -> ToolRecord | None:
    # OpenAI-style: {"type":"function", "function":{"name":...,"description":...}}
    fn = item.get("function")
    if isinstance(fn, dict) and isinstance(fn.get("name"), str):
        return ToolRecord(str(fn["name"]), str(fn.get("description", "")), source)

    # MCP-like or generic tool object: {"name":..., "description":..., "inputSchema":...}
    if isinstance(item.get("name"), str) and (
        "inputSchema" in item or "input_schema" in item or item.get("type") == "tool"
    ):
        return ToolRecord(str(item["name"]), str(item.get("description", "")), source)
    return None


def _walk(value: Any, source: str, out: list[ToolRecord]) -> None:
    if isinstance(value, dict):
        direct = _tool_from_mapping(value, source)
        if direct:
            out.append(direct)
        for key, child in value.items():
            if key in {"tools", "functions"} and isinstance(child, list):
                for item in child:
                    if isinstance(item, dict):
                        tool = _tool_from_mapping(item, source)
                        if tool:
                            out.append(tool)
                        else:
                            _walk(item, source, out)
            elif isinstance(child, (dict, list)):
                _walk(child, source, out)
    elif isinstance(value, list):
        for child in value:
            _walk(child, source, out)


def discover_tools(root: Path) -> list[ToolRecord]:
    candidates = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
    found: list[ToolRecord] = []
    for path in candidates:
        if path.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        try:
            data = _read(path)
        except (OSError, ValueError, yaml.YAMLError):
            continue
        _walk(data, str(path), found)

    dedup: dict[tuple[str, str], ToolRecord] = {}
    for tool in found:
        dedup[(tool.name, tool.source)] = tool
    return sorted(dedup.values(), key=lambda x: (x.name.lower(), x.source))
