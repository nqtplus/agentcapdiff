from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from .models import ScopeEvidence, ToolRecord

PATH_NAMES = {
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
NET_NAMES = {
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
LITERALS = {"const", "enum", "default", "examples"}
DYNAMIC = ("${", "{{", "}}", "<", ">")


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for part in value for item in _strings(part)]
    return []


def _literals(schema: dict[str, Any] | None, names: set[str]) -> list[str]:
    if not schema:
        return []
    out: list[str] = []
    stack: list[tuple[Any, str | None]] = [(schema, None)]
    seen: set[int] = set()
    while stack:
        current, context = stack.pop()
        if not isinstance(current, (dict, list)):
            continue
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, list):
            stack.extend(
                (item, context)
                for item in current
                if isinstance(item, (dict, list))
            )
            continue
        for key, value in current.items():
            key_l = str(key).lower()
            if key_l == "properties" and isinstance(value, dict):
                stack.extend(
                    (child, str(name).lower())
                    for name, child in value.items()
                    if isinstance(child, (dict, list))
                )
                continue
            if context in names and key_l in LITERALS:
                out.extend(_strings(value))
            if isinstance(value, (dict, list)):
                stack.append((value, key_l if key_l in names else context))
    return out


def _path_description(text: str) -> list[str]:
    values: list[str] = []
    patterns = (
        r"(?:restricted|limited) to\s+([./~A-Za-z0-9_*?\\:-]+)",
        r"only (?:under|within|in)\s+([./~A-Za-z0-9_*?\\:-]+)",
    )
    for pattern in patterns:
        values.extend(m.group(1) for m in re.finditer(pattern, text, re.I))
    return values


def _path(value: str) -> str | None:
    raw = value.strip().replace("\\", "/")
    if not raw or "\x00" in raw or any(marker in raw for marker in DYNAMIC):
        return None
    if re.search(r"(^|/)\.\.(/|$)", raw):
        return None
    if raw in {"*", "**", "/", "/*", "/**"}:
        return "/**"
    prefix = "./" if raw.startswith("./") else "/" if raw.startswith("/") else ""
    body = raw[2:] if prefix == "./" else raw[1:] if prefix == "/" else raw
    normalized = posixpath.normpath(body)
    result = prefix + normalized
    if raw.endswith("/**") and not result.endswith("/**"):
        result = result.rstrip("/") + "/**"
    return result


def infer_filesystem_scope(tool: ToolRecord) -> ScopeEvidence:
    text = tool.description or ""
    if re.search(
        r"\b(?:any|arbitrary|unrestricted)\s+(?:file|path|directory)",
        text,
        re.I,
    ):
        return ScopeEvidence(
            "broad",
            ("/**",),
            "Description explicitly permits arbitrary paths.",
        )
    raw = _literals(tool.input_schema, PATH_NAMES) + _path_description(text)
    if not raw:
        return ScopeEvidence()
    values: list[str] = []
    for value in raw:
        normalized = _path(value)
        if normalized is None:
            return ScopeEvidence(
                "unknown",
                (),
                "Path constraint is dynamic, traversing, or cannot be normalized safely.",
            )
        values.append(normalized)
    unique = tuple(sorted(set(values)))
    if "/**" in unique:
        return ScopeEvidence(
            "broad",
            unique,
            "Static input permits filesystem-root-wide access.",
        )
    return ScopeEvidence(
        "restricted",
        unique,
        "Static input exposes a finite path constraint.",
    )


def _net_description(text: str) -> list[str]:
    values: list[str] = []
    patterns = (
        r"(?:only|restricted|limited) to\s+(https?://[^\s,;]+)",
        r"(?:only|restricted|limited) to\s+((?:\*\.)?[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    )
    for pattern in patterns:
        values.extend(m.group(1) for m in re.finditer(pattern, text, re.I))
    return values


def _net(value: str) -> str | None:
    raw = value.strip().rstrip(".,;)")
    if not raw or "\x00" in raw or any(marker in raw for marker in DYNAMIC):
        return None
    if raw in {
        "*",
        "*.*",
        "http://*",
        "https://*",
        "http://**",
        "https://**",
    }:
        return "*"
    if raw.startswith("*."):
        host = raw[2:].lower().strip(".")
        return f"*.{host}" if host and "/" not in host else None
    candidate = raw if "://" in raw else f"https://{raw}"
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        port_value = parsed.port
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not host:
        return None
    host = host.lower().rstrip(".")
    if host in {"*", "0.0.0.0"}:
        return "*"
    port = f":{port_value}" if port_value is not None else ""
    if "://" not in raw and parsed.path in {"", "/"}:
        return f"{host}{port}"
    return f"{parsed.scheme}://{host}{port}{parsed.path or '/'}"


def infer_network_scope(tool: ToolRecord) -> ScopeEvidence:
    text = tool.description or ""
    if re.search(
        r"\b(?:any|arbitrary|unrestricted)\s+(?:url|domain|host|endpoint|website)",
        text,
        re.I,
    ):
        return ScopeEvidence(
            "broad",
            ("*",),
            "Description explicitly permits arbitrary destinations.",
        )
    raw = _literals(tool.input_schema, NET_NAMES) + _net_description(text)
    if not raw:
        return ScopeEvidence()
    values: list[str] = []
    for value in raw:
        normalized = _net(value)
        if normalized is None:
            return ScopeEvidence(
                "unknown",
                (),
                "Network destination is dynamic or cannot be normalized conservatively.",
            )
        values.append(normalized)
    unique = tuple(sorted(set(values)))
    if "*" in unique:
        return ScopeEvidence(
            "broad",
            unique,
            "Static input permits arbitrary network destinations.",
        )
    return ScopeEvidence(
        "restricted",
        unique,
        "Static input exposes a finite destination constraint.",
    )


def scope_for_capability(capability_id: str, tool: ToolRecord) -> ScopeEvidence:
    if capability_id.startswith("filesystem."):
        return infer_filesystem_scope(tool)
    if capability_id == "network.external":
        return infer_network_scope(tool)
    return ScopeEvidence()


def _covers(head: str, base: str) -> bool:
    if head == base:
        return True
    if head.endswith("/**"):
        return base.startswith(head[:-3].rstrip("/") + "/")
    if head.startswith("*."):
        suffix = head[1:].lower()
        candidate = base.lower()
        if "://" in candidate:
            try:
                candidate = (urlsplit(candidate).hostname or "").lower()
            except ValueError:
                return False
        return candidate.endswith(suffix)
    return False


def scope_is_expansion(base: dict[str, Any], head: dict[str, Any]) -> bool:
    base_kind = str(base.get("kind", "unknown"))
    head_kind = str(head.get("kind", "unknown"))
    if base_kind == "restricted" and head_kind == "broad":
        return True
    if base_kind != "restricted" or head_kind != "restricted":
        return False
    before = set(str(v) for v in base.get("values", []))
    after = set(str(v) for v in head.get("values", []))
    if not before or not after or before == after:
        return False
    if after > before:
        return True
    return all(any(_covers(h, b) for h in after) for b in before)


def scope_records(capabilities: Iterable[Any]) -> list[dict[str, Any]]:
    records = []
    for cap in capabilities:
        if cap.id.startswith("filesystem.") or cap.id == "network.external":
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
