from __future__ import annotations

import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass
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
    "destination_path",
    "input_path",
    "output_path",
    "read_path",
    "source_path",
    "target_path",
    "write_path",
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
    "destination_url",
    "remote_url",
    "request_url",
    "target_url",
    "webhook_url",
}
DYNAMIC = ("${", "{{", "}}", "<", ">")


@dataclass(frozen=True)
class _ConstraintEvidence:
    values: tuple[str, ...] = ()
    mentioned: bool = False
    ambiguous: bool = False


def _normalize_label(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    value = re.sub(r"[^A-Za-z0-9]+", "_", value)
    return value.strip("_").lower()


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for part in value for item in _strings(part)]
    return []


def _mentions_scope(value: Any, names: set[str]) -> bool:
    stack = [value]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if not isinstance(current, (dict, list)):
            continue
        object_id = id(current)
        if object_id in seen:
            continue
        seen.add(object_id)
        if isinstance(current, list):
            stack.extend(item for item in current if isinstance(item, (dict, list)))
            continue
        properties = current.get("properties")
        if isinstance(properties, dict) and any(
            _normalize_label(str(name)) in names for name in properties
        ):
            return True
        stack.extend(item for item in current.values() if isinstance(item, (dict, list)))
    return False


def _finite_literals(schema: dict[str, Any]) -> tuple[str, ...]:
    values: list[str] = []
    if "const" in schema:
        values.extend(_strings(schema.get("const")))
    if "enum" in schema:
        values.extend(_strings(schema.get("enum")))
    return tuple(sorted(set(values)))


def _value_constraints(schema: Any, active: set[int] | None = None) -> _ConstraintEvidence:
    if not isinstance(schema, dict):
        return _ConstraintEvidence(mentioned=True, ambiguous=True)

    active = set() if active is None else active
    object_id = id(schema)
    if object_id in active:
        return _ConstraintEvidence(mentioned=True, ambiguous=True)
    active.add(object_id)
    try:
        hard_values = set(_finite_literals(schema))

        all_of = schema.get("allOf")
        if isinstance(all_of, list):
            for branch in all_of:
                evidence = _value_constraints(branch, active)
                if evidence.values:
                    hard_values.update(evidence.values)

        items = schema.get("items")
        if isinstance(items, dict):
            evidence = _value_constraints(items, active)
            if evidence.values:
                hard_values.update(evidence.values)

        # Any unconditional finite upper bound is conservative even when another
        # conjunctive keyword is dynamic or unresolved.
        if hard_values:
            return _ConstraintEvidence(tuple(sorted(hard_values)), True, False)

        for keyword in ("anyOf", "oneOf"):
            branches = schema.get(keyword)
            if not isinstance(branches, list) or not branches:
                continue
            evidence = [_value_constraints(branch, active) for branch in branches]
            if all(item.values and not item.ambiguous for item in evidence):
                values = tuple(sorted({value for item in evidence for value in item.values}))
                return _ConstraintEvidence(values, True, False)
            return _ConstraintEvidence(mentioned=True, ambiguous=True)

        if "if" in schema:
            branches = [schema.get("then"), schema.get("else")]
            if all(isinstance(branch, dict) for branch in branches):
                evidence = [_value_constraints(branch, active) for branch in branches]
                if all(item.values and not item.ambiguous for item in evidence):
                    values = tuple(sorted({value for item in evidence for value in item.values}))
                    return _ConstraintEvidence(values, True, False)
            return _ConstraintEvidence(mentioned=True, ambiguous=True)

        # `not`, unresolved `$ref`, patterns, formats, defaults and examples do not
        # establish a finite authorization boundary by themselves.
        return _ConstraintEvidence(mentioned=True, ambiguous=True)
    finally:
        active.remove(object_id)


def _merge_schema_evidence(parts: list[_ConstraintEvidence]) -> _ConstraintEvidence:
    mentioned = any(part.mentioned for part in parts)
    ambiguous = any(part.ambiguous for part in parts)
    values = tuple(sorted({value for part in parts for value in part.values}))
    return _ConstraintEvidence(values, mentioned, ambiguous)


def _alternative_schema_evidence(
    branches: list[Any],
    names: set[str],
    active: set[int],
) -> _ConstraintEvidence:
    evidence = [_schema_constraints(branch, names, active) for branch in branches]
    if not any(item.mentioned for item in evidence):
        return _ConstraintEvidence()
    if all(item.mentioned and item.values and not item.ambiguous for item in evidence):
        values = tuple(sorted({value for item in evidence for value in item.values}))
        return _ConstraintEvidence(values, True, False)
    return _ConstraintEvidence(mentioned=True, ambiguous=True)


def _schema_constraints(
    schema: Any,
    names: set[str],
    active: set[int] | None = None,
) -> _ConstraintEvidence:
    if not isinstance(schema, dict):
        return _ConstraintEvidence()

    active = set() if active is None else active
    object_id = id(schema)
    if object_id in active:
        return _ConstraintEvidence(mentioned=True, ambiguous=True)
    active.add(object_id)
    try:
        parts: list[_ConstraintEvidence] = []

        # A root reference can replace the whole input schema. AgentCapDiff does not
        # resolve arbitrary references, so a reassuring description cannot turn it
        # into a proven restriction.
        if "$ref" in schema:
            parts.append(_ConstraintEvidence(mentioned=True, ambiguous=True))

        properties = schema.get("properties")
        if isinstance(properties, dict):
            for name, child in properties.items():
                normalized = _normalize_label(str(name))
                if normalized in names:
                    parts.append(_value_constraints(child, active))
                elif isinstance(child, dict):
                    nested = _schema_constraints(child, names, active)
                    if nested.mentioned:
                        parts.append(nested)

        all_of = schema.get("allOf")
        if isinstance(all_of, list):
            parts.extend(
                evidence
                for branch in all_of
                if (evidence := _schema_constraints(branch, names, active)).mentioned
            )

        for keyword in ("anyOf", "oneOf"):
            branches = schema.get(keyword)
            if isinstance(branches, list) and branches:
                alternative = _alternative_schema_evidence(branches, names, active)
                if alternative.mentioned:
                    parts.append(alternative)

        items = schema.get("items")
        if isinstance(items, dict):
            nested = _schema_constraints(items, names, active)
            if nested.mentioned:
                parts.append(nested)

        if "if" in schema:
            condition_mentions = _mentions_scope(schema.get("if"), names)
            then_branch = schema.get("then")
            else_branch = schema.get("else")
            conditional = _alternative_schema_evidence(
                [then_branch, else_branch],
                names,
                active,
            )
            if conditional.mentioned:
                parts.append(conditional)
            elif condition_mentions:
                parts.append(_ConstraintEvidence(mentioned=True, ambiguous=True))

        negative = schema.get("not")
        if _mentions_scope(negative, names):
            parts.append(_ConstraintEvidence(mentioned=True, ambiguous=True))

        dependent = schema.get("dependentSchemas")
        if _mentions_scope(dependent, names):
            parts.append(_ConstraintEvidence(mentioned=True, ambiguous=True))

        # `$defs`/`definitions` are deliberately not traversed: an unused definition
        # is not an applied authorization constraint.
        return _merge_schema_evidence(parts)
    finally:
        active.remove(object_id)


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

    schema = _schema_constraints(tool.input_schema, PATH_NAMES)
    if schema.mentioned and schema.ambiguous:
        return ScopeEvidence(
            "unknown",
            (),
            "Path schema does not establish a proven finite constraint because it is "
            "optional, alternative, negative, unresolved, or otherwise ambiguous.",
        )

    raw = list(schema.values) + _path_description(text)
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

    schema = _schema_constraints(tool.input_schema, NET_NAMES)
    if schema.mentioned and schema.ambiguous:
        return ScopeEvidence(
            "unknown",
            (),
            "Network schema does not establish a proven finite constraint because it is "
            "optional, alternative, negative, unresolved, or otherwise ambiguous.",
        )

    raw = list(schema.values) + _net_description(text)
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
        prefix = head[:-3].rstrip("/")
        return base == prefix or base.startswith(prefix + "/")
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


def scope_uncertainty_increased(base: dict[str, Any], head: dict[str, Any]) -> bool:
    """Return true when a previously proven restriction becomes unknown.

    This is intentionally separate from `scope_is_expansion`: unknown evidence does
    not prove runtime broadening, but losing a finite static bound still requires
    explicit reviewer attention.
    """

    return str(base.get("kind", "unknown")) == "restricted" and str(
        head.get("kind", "unknown")
    ) == "unknown"


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
