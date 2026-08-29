from __future__ import annotations

import json
from typing import Any

from .graph import build_capability_graph, capability_graph_to_record
from .models import Capability
from .schema import (
    VALID_CONFIDENCE,
    VALID_SCOPE_KINDS,
    capability_from_record,
    capability_to_record,
)
from .scopes import scope_records

_SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _require_string(value: Any, field: str, *, non_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if non_empty and not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _require_string_list(value: Any, field: str) -> list[str]:
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must be a list of strings")
    return list(value)


def _validate_capability_records(snapshot: dict[str, Any]) -> list[Capability] | None:
    raw = snapshot.get("capability_records")
    if raw is None:
        return None
    if not isinstance(raw, list) or not all(isinstance(item, dict) for item in raw):
        raise ValueError("capability_records must be a list of objects")

    capabilities: list[Capability] = []
    seen: dict[tuple[str, str, str], str] = {}
    for index, item in enumerate(raw):
        prefix = f"capability_records[{index}]"
        version = _require_string(item.get("schema_version"), f"{prefix}.schema_version")
        if version != "1":
            raise ValueError(f"{prefix}.schema_version must be 1")
        _require_string(item.get("id"), f"{prefix}.id", non_empty=True)
        _require_string(item.get("tool"), f"{prefix}.tool", non_empty=True)
        _require_string(item.get("reason"), f"{prefix}.reason")
        _require_string(item.get("source"), f"{prefix}.source")

        risk = item.get("risk")
        if isinstance(risk, bool) or not isinstance(risk, int) or not 0 <= risk <= 100:
            raise ValueError(f"{prefix}.risk must be an integer from 0 to 100")

        confidence = item.get("confidence")
        if confidence not in VALID_CONFIDENCE:
            raise ValueError(f"{prefix}.confidence is invalid")

        scope = item.get("scope")
        if not isinstance(scope, dict):
            raise ValueError(f"{prefix}.scope must be an object")
        if scope.get("kind") not in VALID_SCOPE_KINDS:
            raise ValueError(f"{prefix}.scope.kind is invalid")
        _require_string_list(scope.get("values"), f"{prefix}.scope.values")
        _require_string(scope.get("reason"), f"{prefix}.scope.reason")

        evidence = item.get("evidence")
        if not isinstance(evidence, list) or not all(isinstance(entry, dict) for entry in evidence):
            raise ValueError(f"{prefix}.evidence must be a list of objects")
        for evidence_index, entry in enumerate(evidence):
            evidence_prefix = f"{prefix}.evidence[{evidence_index}]"
            for field in ("adapter", "source", "signal"):
                _require_string(entry.get(field), f"{evidence_prefix}.{field}")

        capability = capability_from_record(item)
        identity = (capability.id, capability.tool, capability.source)
        semantic = _canonical(capability_to_record(capability))
        previous = seen.get(identity)
        if previous is not None and previous != semantic:
            raise ValueError(
                "capability_records contain conflicting records for identity "
                f"{identity!r}"
            )
        seen[identity] = semantic
        capabilities.append(capability)
    return capabilities


def _scope_projection(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "capability": item.get("capability"),
        "tool": item.get("tool"),
        "kind": item.get("kind"),
        "values": list(item.get("values", [])) if isinstance(item.get("values", []), (list, tuple)) else item.get("values", []),
        "reason": item.get("reason", ""),
    }


def _validate_scopes(
    snapshot: dict[str, Any],
    capabilities: list[Capability] | None,
    capability_ids: set[str],
    tool_names: set[str],
    *,
    has_capabilities: bool,
    has_tools: bool,
) -> None:
    raw = snapshot.get("scopes")
    if raw is None:
        return
    if not isinstance(raw, list) or not all(isinstance(item, dict) for item in raw):
        raise ValueError("scopes must be a list of objects")

    seen: dict[tuple[str, str], str] = {}
    for index, item in enumerate(raw):
        prefix = f"scopes[{index}]"
        capability = _require_string(item.get("capability"), f"{prefix}.capability", non_empty=True)
        tool = _require_string(item.get("tool"), f"{prefix}.tool", non_empty=True)
        if has_capabilities and capability not in capability_ids:
            raise ValueError(f"{prefix} references capability absent from capabilities")
        if has_tools and tool not in tool_names:
            raise ValueError(f"{prefix} references tool absent from tools")

        projection = _scope_projection(item)
        semantic = _canonical(projection)
        key = (capability, tool)
        previous = seen.get(key)
        if previous is not None and previous != semantic:
            raise ValueError(f"scopes contain conflicting records for {key!r}")
        seen[key] = semantic

    if capabilities is None:
        return
    expected = sorted(_canonical(_scope_projection(item)) for item in scope_records(capabilities))
    actual = sorted(_canonical(_scope_projection(item)) for item in raw)
    if actual != expected:
        raise ValueError("scopes do not match capability_records")


def _graph_projection(graph: dict[str, Any]) -> dict[str, Any]:
    nodes_raw = graph.get("nodes", [])
    edges_raw = graph.get("edges", [])
    paths_raw = graph.get("paths", [])
    if not isinstance(nodes_raw, (list, tuple)) or not all(
        isinstance(item, dict) for item in nodes_raw
    ):
        raise ValueError("capability_graph.nodes must be a list of objects")
    if not isinstance(edges_raw, (list, tuple)) or not all(
        isinstance(item, dict) for item in edges_raw
    ):
        raise ValueError("capability_graph.edges must be a list of objects")
    if not isinstance(paths_raw, (list, tuple)) or not all(
        isinstance(item, dict) for item in paths_raw
    ):
        raise ValueError("capability_graph.paths must be a list of objects")

    nodes: list[dict[str, Any]] = []
    for index, item in enumerate(nodes_raw):
        prefix = f"capability_graph.nodes[{index}]"
        capability = _require_string(item.get("capability"), f"{prefix}.capability", non_empty=True)
        tools = _require_string_list(item.get("tools"), f"{prefix}.tools")
        max_risk = item.get("max_risk")
        if isinstance(max_risk, bool) or not isinstance(max_risk, int) or not 0 <= max_risk <= 100:
            raise ValueError(f"{prefix}.max_risk must be an integer from 0 to 100")
        nodes.append({"capability": capability, "tools": tools, "max_risk": max_risk})

    edges: list[dict[str, Any]] = []
    for index, item in enumerate(edges_raw):
        prefix = f"capability_graph.edges[{index}]"
        edges.append(
            {
                "source": _require_string(item.get("source"), f"{prefix}.source", non_empty=True),
                "target": _require_string(item.get("target"), f"{prefix}.target", non_empty=True),
                "relation": _require_string(
                    item.get("relation"), f"{prefix}.relation", non_empty=True
                ),
            }
        )

    paths: list[dict[str, Any]] = []
    for index, item in enumerate(paths_raw):
        prefix = f"capability_graph.paths[{index}]"
        paths.append(
            {
                "id": _require_string(item.get("id"), f"{prefix}.id", non_empty=True),
                "title": _require_string(item.get("title"), f"{prefix}.title"),
                "severity": _require_string(item.get("severity"), f"{prefix}.severity"),
                "confidence": _require_string(item.get("confidence"), f"{prefix}.confidence"),
                "capabilities": _require_string_list(
                    item.get("capabilities"), f"{prefix}.capabilities"
                ),
                "tools": _require_string_list(item.get("tools"), f"{prefix}.tools"),
                "evidence": _require_string_list(item.get("evidence"), f"{prefix}.evidence"),
                "message": _require_string(item.get("message"), f"{prefix}.message"),
            }
        )

    return {
        "schema_version": graph.get("schema_version"),
        "nodes": nodes,
        "edges": edges,
        "paths": paths,
    }


def _validate_graph(
    snapshot: dict[str, Any],
    capabilities: list[Capability] | None,
    capability_ids: set[str],
    tool_names: set[str],
    *,
    has_capabilities: bool,
    has_tools: bool,
) -> None:
    graph = snapshot.get("capability_graph")
    if graph is None:
        return
    if not isinstance(graph, dict):
        raise ValueError("capability_graph must be an object")
    projection = _graph_projection(graph)

    for index, node in enumerate(projection["nodes"]):
        if has_capabilities and node["capability"] not in capability_ids:
            raise ValueError(
                f"capability_graph.nodes[{index}] references capability absent from capabilities"
            )
        if has_tools and not set(node["tools"]).issubset(tool_names):
            raise ValueError(f"capability_graph.nodes[{index}] references tool absent from tools")
    for index, edge in enumerate(projection["edges"]):
        if has_capabilities and (
            edge["source"] not in capability_ids or edge["target"] not in capability_ids
        ):
            raise ValueError(
                f"capability_graph.edges[{index}] references capability absent from capabilities"
            )
    for index, path in enumerate(projection["paths"]):
        if has_capabilities and not set(path["capabilities"]).issubset(capability_ids):
            raise ValueError(
                f"capability_graph.paths[{index}] references capability absent from capabilities"
            )
        if has_tools and not set(path["tools"]).issubset(tool_names):
            raise ValueError(f"capability_graph.paths[{index}] references tool absent from tools")

    if capabilities is None:
        return
    expected = _graph_projection(capability_graph_to_record(build_capability_graph(capabilities)))
    if _canonical(projection) != _canonical(expected):
        raise ValueError("capability_graph does not match capability_records")


def _validate_findings(
    snapshot: dict[str, Any],
    capability_ids: set[str],
    tool_names: set[str],
    *,
    has_capabilities: bool,
    has_tools: bool,
) -> None:
    findings = snapshot.get("findings")
    if findings is None:
        return
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        raise ValueError("findings must be a list of objects")

    severities: list[str] = []
    for index, item in enumerate(findings):
        capability = item.get("capability")
        tool = item.get("tool")
        if capability is not None and has_capabilities and capability not in capability_ids:
            raise ValueError(f"findings[{index}] references capability absent from capabilities")
        if tool is not None and has_tools and tool not in tool_names:
            raise ValueError(f"findings[{index}] references tool absent from tools")
        severity = item.get("severity", "INFO")
        if isinstance(severity, str) and severity in _SEVERITY_ORDER:
            severities.append(severity)

    if "max_severity" in snapshot:
        expected = max(severities, key=lambda value: _SEVERITY_ORDER[value], default="INFO")
        if snapshot.get("max_severity") != expected:
            raise ValueError("max_severity does not match findings")


def validate_snapshot_semantics(snapshot: dict[str, Any]) -> None:
    """Fail closed when security-relevant snapshot fields contradict each other.

    Legacy snapshots may omit newer additive evidence. Cross-field checks are only
    applied when the corresponding evidence exists; absence is not fabricated.
    """

    capabilities = _validate_capability_records(snapshot)
    has_capabilities = "capabilities" in snapshot
    has_tools = "tools" in snapshot
    capability_ids = (
        set(snapshot.get("capabilities", [])) if isinstance(snapshot.get("capabilities"), list) else set()
    )
    tool_names = set(snapshot.get("tools", [])) if isinstance(snapshot.get("tools"), list) else set()

    if capabilities is not None:
        record_ids = {capability.id for capability in capabilities}
        if has_capabilities and capability_ids != record_ids:
            raise ValueError("capabilities do not match capability_records")
        record_tools = {capability.tool for capability in capabilities}
        if has_tools and not record_tools.issubset(tool_names):
            raise ValueError("capability_records reference tools absent from tools")

        if "risk_score" in snapshot:
            by_id: dict[str, int] = {}
            for capability in capabilities:
                by_id[capability.id] = max(by_id.get(capability.id, 0), capability.risk)
            expected_risk = min(100, sum(by_id.values()))
            if snapshot.get("risk_score") != expected_risk:
                raise ValueError("risk_score does not match capability_records")

    _validate_scopes(
        snapshot,
        capabilities,
        capability_ids,
        tool_names,
        has_capabilities=has_capabilities,
        has_tools=has_tools,
    )
    _validate_graph(
        snapshot,
        capabilities,
        capability_ids,
        tool_names,
        has_capabilities=has_capabilities,
        has_tools=has_tools,
    )
    _validate_findings(
        snapshot,
        capability_ids,
        tool_names,
        has_capabilities=has_capabilities,
        has_tools=has_tools,
    )
