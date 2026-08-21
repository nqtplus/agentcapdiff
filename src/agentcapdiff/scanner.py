from __future__ import annotations

from pathlib import Path

from .capabilities import infer_capabilities
from .discovery import discover_tools
from .models import ScanResult
from .policy import evaluate_policy, load_policy


def scan(path: Path, policy_path: Path | None = None) -> ScanResult:
    tools = discover_tools(path)
    caps = infer_capabilities(tools)
    result = ScanResult(tools=tools, capabilities=caps)
    policy = load_policy(policy_path)
    result.findings = evaluate_policy(caps, policy, result.risk_score)
    return result
