from __future__ import annotations

from pathlib import Path

from .capabilities import infer_capabilities
from .discovery import discover_tools
from .graph import build_capability_graph, capability_graph_to_record
from .models import ScanResult
from .policy import evaluate_policy, load_policy, policy_to_record


def scan(path: Path, policy_path: Path | None = None) -> ScanResult:
    tools = discover_tools(path)
    caps = infer_capabilities(tools)
    graph = build_capability_graph(caps)
    policy = load_policy(policy_path)
    result = ScanResult(
        tools=tools,
        capabilities=caps,
        capability_graph=capability_graph_to_record(graph),
        policy=policy_to_record(policy),
    )
    result.findings = evaluate_policy(caps, policy, result.risk_score)
    result.seal(policy)
    return result
