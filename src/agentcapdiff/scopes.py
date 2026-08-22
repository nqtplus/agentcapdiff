from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from .models import ScopeEvidence, ToolRecord

_PATH_NAMES = {
    "path",
    "paths",
    "file",
    "filepath",
    "file_path",
    "directory",
    "dir",
    "root",
    "allowed_path",
    "allowed_paths",
    "base_path",
}
_NETWORK_NAMES = {
    "url",
    "urls",
    "uri",
    "endpoint",
    "endpoints",
    "domain",
    "domains",
    "host",
    "hosts",
    "base_url",
    "allowed_domains",
    "allowed_hosts",
}
_LITERAL_KEYS = {"const", "enum", "default", "examples"}
_DYNAMIC_MARKERS = ("${", "{{", "}}", "<", ">")


def _flatten_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for value_item in value for item in _flatten_strings(value_item)]
    return []


def _schema_literals(schema: dict[str, Any] | None, names: set[str]) -> list[str]:
    if not schema:
        return []
    out: list[str] = []
    stack: list[tuple[Any, str | None]] = [(schema, None)]
    visited: set[int] = set()
    while stack:
        current, context = stack.pop()
        if not isinstance(current, (dict, list)):
            continue
        object_id = id(current)
        if object_id in visited:
            continue
        visited.add(object_id)
        if isinstance(current, list):
            stack.extend((item, context) for item in current if isinstance(item, (dict, list)))
            continue
        for key, value in current.items():
            key_lower = str(key).lower()
            next_context = context
            if key_lower in names:
                next_context = key_lower
            if key_lower == "properties" and isinstance(value, dict):
                for prop_name, prop_schema in value.items():
                    prop_context = str(prop_name).lower()
                    if isinstance(prop_schema, (dict, list)):
                        stack.append((prop_schema, prop_context))
                continue
            if context in names and key_lower in _LITERAL_KEYS:
                out.extend(_flatten_strings(value))
            if isinstance(value, (dict, list)):
                stack.append((value, next_context))
    return out


def _description_paths(description: str) -> list[str]:
    patterns = (
        r"(?:restricted|limited) to\s+([./~A-Za-z0-9_*?\\:-]+)",
        r"only (?:under|within|in)\s+([./~A-Za-z0-9_*?\\:-]+)",
    )
    values: list[str] = []
    for pattern in patterns:
        values.extend(match.group(1) for match in re.finditer(pattern, description, re.I))
    return values


def _normalize_path(value: str) -> str | None:
    raw = value.strip().replace("\\", "/")
    if not raw or "\x00" in raw or any(marker in raw for marker in _DYNAMIC_MARKERS):
        return None
    if re.search(r"(^|/)\.\.(/|$)", raw):
        return None
    if raw in {"*", "**", "/", "/*", "/**"}:
        return "/**"
    prefix = "./" if raw.startswith("./") else "/" if raw.startswith("/") else ""
    body = raw[2:] if prefix == "./" else raw[1:] if prefix == "/" else raw
    normalized = posixpath.normpath(body)
    if normalized in {".", ""} and prefix == "/":
        return "/**"
    result = prefix + normalized
    if raw.endswith("/**") and not result.endswith("/**"):
        result = result.rstrip("/") + "/**"
    return result


def infer_filesystem_scope(tool: ToolRecord) -> ScopeEvidence:
    text = tool.description or ""
    if re.search(r"\b(?:any|arbitrary|unrestricted)\s+(?:file|path|directory)", text, re.I):
        return ScopeEvidence("broad", ("/**",), "Description explicitly permits arbitrary paths.")

    raw_values = _schema_literals(tool.input_schema, _PATH_NAMES) + _description_paths(text)
    if not raw_values:
        return ScopeEvidence()
    normalized: list[str] = []
    for value in raw_values:
        item = _normalize_path(value)
        if item is None:
            return ScopeEvidence(
                "unknown",
                (),
                "Path constraint is dynamic, traversing, or cannot be normalized safely.",
            )
        normalized.append(item)
    unique = tuple(sorted(set(normalized)))
    if "/**" in unique:
        return ScopeEvidence("broad", unique, "Static input permits filesystem-root-wide access.")
    return ScopeEvidence("restricted", unique, "Static input exposes a finite path constraint.")


def _description_network_values(description: str) -> list[str]:
    patterns = (
        r"(?:only|restricted|limited) to\s+(https?://[^\s,;]+)",
        r"(?:only|restricted|limited) to\s+((?:\*\.)?[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    )
    values: list[str] = []
    for pattern in patterns:
        values.extend(match.group(1) for match in re.finditer(pattern, description, re.I))
    return values


def _normalize_network(value: str) -> str | None:
    raw = value.strip().rstrip(".,;)")
    if not raw or "\x00" in raw or any(marker in raw for marker in _DYNAMIC_MARKERS):
        return None
    if raw in {"*", "*.*", "http://*", "https://*", "http://**", "https://**"}:
        return "*"
    if raw.startswith("*."):
        host = raw[2:].lower().strip(".")
        if not host or "/" in host:
            return None
        return f"*.{host}"
    candidate = raw if "://" in raw else f"https://{raw}"
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname.lower().rstrip(".")
    if host in {"*", "0.0.0.0"}:
        return "*"
    port = f":{parsed.port}" if parsed.port is not None else ""
    if "://" not in raw and parsed.path in {"", "/"}:
        return f"{host}{port}"
    path = parsed.path or "/"
    return f"{parsed.scheme}://{host}{port}{path}"


def infer_network_scope(tool: ToolRecord) -> ScopeEvidence:
    text = tool.description or ""
    if re.search(r"\b(?:any|arbitrary|unrestricted)\s+(?:url|domain|host|endpoint|website)", text, re.I):
        return ScopeEvidence("broad", ("*",), "Description explicitly permits arbitrary destinations.")

    raw_values = _schema_literals(tool.input_schema, _NETWORK_NAMES) + _description_network_values(text)
    if not raw_values:
        return ScopeEvidence()
    normalized: list[str] = []
    for value in raw_values:
        item = _normalize_network(value)
        if item is None:
            return ScopeEvidence(
                "unknown",
                (),
                "Network destination is dynamic or cannot be normalized conservatively.",
            )
        normalized.append(item)
    unique = tuple(sorted(set(normalized)))
    if "*" in unique:
        return ScopeEvidence("broad", unique, "Static input permits arbitrary network destinations.")
    return ScopeEvidence("restricted", unique, "Static input exposes a finite destination constraint.")


def scope_for_capability(capability_id: str, tool: ToolRecord) -> ScopeEvidence:
    if capability_id.startswith("filesystem."):
        return infer_filesystem_scope(tool)
    if capability_id == "network.external":
        return infer_network_scope(tool)
    return ScopeEvidence()


def scope_is_expansion(base: dict[str, Any], head: dict[str, Any]) -> bool:
    """Return True only for scope expansions established by static evidence."""
    base_kind = str(base.get("kind", "unknown"))
    head_kind = str(head.get("kind", "unknown"))
    if base_kind == "restricted" and head_kind == "broad":
        return True
    if base_kind != "restricted" or head_kind != "restricted":
        return False
    base_values = set(str(v) for v in base.get("values", []))
    head_values = set(str(v) for v in head.get("values", []))
    return bool(base_values) and head_values > base_values


def scope_records(capabilities: Iterable[Any]) -> list[dict[str, Any]]:
    records = []
    for cap in capabilities:
        if not (cap.id.startswith("filesystem.") or cap.id == "network.external"):
            continue
        records.append(
            {
                "capability": cap.id,
                "tool": cap.tool,
                "kind": cap.scope.kind,
                "values": list(cap.scope.values),
                "reason": cap.scope.reason,
            }
        )
    return sorted(records, key=lambda item: (item["capability"], item["tool"]))
