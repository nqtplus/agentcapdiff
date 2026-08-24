from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .models import Capability

CAPABILITY_GRAPH_SCHEMA_VERSION = "1"

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass(frozen=True)
class CapabilityGraphNode:
    capability: str
    tools: tuple[str, ...]
    max_risk: int


@dataclass(frozen=True)
class CapabilityGraphEdge:
    source: str
    target: str
    relation: str


@dataclass(frozen=True)
class CapabilityPath:
    id: str
    title: str
    severity: str
    confidence: str
    capabilities: tuple[str, ...]
    tools: tuple[str, ...]
    evidence: tuple[str, ...]
    message: str


@dataclass(frozen=True)
class CapabilityGraph:
    schema_version: str
    nodes: tuple[CapabilityGraphNode, ...]
    edges: tuple[CapabilityGraphEdge, ...]
    paths: tuple[CapabilityPath, ...]


@dataclass(frozen=True)
class PathRule:
    id: str
    title: str
    required: tuple[str, ...]
    base_severity: str
    relation: str
    scope_sensitive: tuple[str, ...] = ()


PATH_RULES = (
    PathRule(
        id="possible.secrets_network_exfiltration",
        title="Possible credential/data exfiltration path",
        required=("secrets.access", "network.external"),
        base_severity="MEDIUM",
        relation="credential-to-network-egress",
        scope_sensitive=("network.external",),
    ),
    PathRule(
        id="possible.filesystem_email_egress",
        title="Possible file-to-email data egress path",
        required=("filesystem.read", "email.send"),
        base_severity="MEDIUM",
        relation="filesystem-to-message-egress",
        scope_sensitive=("filesystem.read",),
    ),
    PathRule(
        id="possible.secrets_email_egress",
        title="Possible credential-to-email egress path",
        required=("secrets.access", "email.send"),
        base_severity="HIGH",
        relation="credential-to-message-egress",
    ),
    PathRule(
        id="possible.github_shell_supply_chain_mutation",
        title="Possible supply-chain mutation path",
        required=("github.write", "shell.execute"),
        base_severity="HIGH",
        relation="execution-to-source-control-mutation",
    ),
)


def _severity_for_rule(rule: PathRule, by_id: dict[str, list[Capability]]) -> str:
    severity = rule.base_severity
    for capability_id in rule.scope_sensitive:
        scopes = {cap.scope.kind for cap in by_id.get(capability_id, [])}
        if "broad" in scopes or "unknown" in scopes:
            severity = max(
                severity,
                "HIGH",
                key=lambda value: SEVERITY_ORDER.get(value, 0),
            )
    return severity


def _confidence_for_rule(rule: PathRule, by_id: dict[str, list[Capability]]) -> str:
    confidence = "high"
    for capability_id in rule.required:
        for cap in by_id.get(capability_id, []):
            if CONFIDENCE_ORDER.get(cap.confidence, 0) < CONFIDENCE_ORDER[confidence]:
                confidence = cap.confidence if cap.confidence in CONFIDENCE_ORDER else "low"
    for capability_id in rule.scope_sensitive:
        scopes = {cap.scope.kind for cap in by_id.get(capability_id, [])}
        if "unknown" in scopes:
            return "low"
    return confidence


def _path_evidence(rule: PathRule, by_id: dict[str, list[Capability]]) -> tuple[str, ...]:
    evidence: list[str] = []
    for capability_id in rule.required:
        for cap in sorted(by_id[capability_id], key=lambda item: (item.tool, item.source)):
            scope_values = ", ".join(cap.scope.values) if cap.scope.values else "not established"
            evidence.append(
                f"{capability_id} via {cap.tool}; scope={cap.scope.kind} ({scope_values}); "
                f"confidence={cap.confidence}"
            )
    return tuple(evidence)


def build_capability_graph(capabilities: list[Capability]) -> CapabilityGraph:
    """Build a deterministic static graph from already-inferred capabilities.

    The graph records possible compositional risk paths only. It does not establish
    runtime reachability or exploitability and performs no target execution or probing.
    """
    by_id: dict[str, list[Capability]] = {}
    for cap in capabilities:
        by_id.setdefault(cap.id, []).append(cap)

    nodes = tuple(
        CapabilityGraphNode(
            capability=capability_id,
            tools=tuple(sorted({cap.tool for cap in caps})),
            max_risk=max(cap.risk for cap in caps),
        )
        for capability_id, caps in sorted(by_id.items())
    )

    paths: list[CapabilityPath] = []
    edges: list[CapabilityGraphEdge] = []
    available = set(by_id)
    for rule in PATH_RULES:
        if not set(rule.required).issubset(available):
            continue
        severity = _severity_for_rule(rule, by_id)
        confidence = _confidence_for_rule(rule, by_id)
        tools = tuple(
            sorted(
                {
                    cap.tool
                    for capability_id in rule.required
                    for cap in by_id[capability_id]
                }
            )
        )
        message = (
            f"{rule.title}: static capability evidence shows "
            f"{' + '.join(rule.required)}. This is a possible path only; "
            "runtime reachability and exploitability are not established."
        )
        paths.append(
            CapabilityPath(
                id=rule.id,
                title=rule.title,
                severity=severity,
                confidence=confidence,
                capabilities=tuple(rule.required),
                tools=tools,
                evidence=_path_evidence(rule, by_id),
                message=message,
            )
        )
        for source, target in zip(rule.required, rule.required[1:], strict=False):
            edges.append(
                CapabilityGraphEdge(
                    source=source,
                    target=target,
                    relation=rule.relation,
                )
            )

    edge_map = {(edge.source, edge.target, edge.relation): edge for edge in edges}
    return CapabilityGraph(
        schema_version=CAPABILITY_GRAPH_SCHEMA_VERSION,
        nodes=nodes,
        edges=tuple(edge_map[key] for key in sorted(edge_map)),
        paths=tuple(sorted(paths, key=lambda item: item.id)),
    )


def capability_graph_to_record(graph: CapabilityGraph) -> dict[str, Any]:
    """Serialize the graph to a stable JSON-compatible record."""
    return asdict(graph)
