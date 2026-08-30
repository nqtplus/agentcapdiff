import json
from pathlib import Path

import pytest

from agentcapdiff.graph import build_capability_graph, capability_graph_to_record
from agentcapdiff.models import Capability, Finding, ScanResult, ToolRecord
from agentcapdiff.policy import Policy, evaluate_policy, policy_to_record
from agentcapdiff.result_semantics import ScanResultConsistencyError
from agentcapdiff.scanner import scan


def _sealed_result(policy: Policy | None = None) -> ScanResult:
    effective_policy = policy or Policy(max_risk_score=100)
    tools = [ToolRecord(name="reader", description="Read files", source="tools.json")]
    capabilities = [
        Capability(
            id="filesystem.read",
            tool="reader",
            risk=10,
            reason="test evidence",
            source="tools.json",
        )
    ]
    result = ScanResult(
        tools=tools,
        capabilities=capabilities,
        capability_graph=capability_graph_to_record(build_capability_graph(capabilities)),
        policy=policy_to_record(effective_policy),
    )
    result.findings = evaluate_policy(capabilities, effective_policy, result.risk_score)
    result.seal(effective_policy)
    return result


def test_scan_returns_sealed_consistent_result(tmp_path: Path) -> None:
    payload = {
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read one file",
                },
            }
        ]
    }
    (tmp_path / "tools.json").write_text(json.dumps(payload), encoding="utf-8")

    result = scan(tmp_path)

    assert result._semantic_fingerprint is not None
    result.assert_consistent()
    assert result.to_dict()["risk_score"] == result.risk_score


def test_seal_rejects_policy_findings_that_do_not_match_policy() -> None:
    policy = Policy(deny={"filesystem.read"}, max_risk_score=100)
    tools = [ToolRecord(name="reader")]
    capabilities = [
        Capability(id="filesystem.read", tool="reader", risk=10, reason="test evidence")
    ]
    result = ScanResult(
        tools=tools,
        capabilities=capabilities,
        capability_graph=capability_graph_to_record(build_capability_graph(capabilities)),
        policy=policy_to_record(policy),
        findings=[],
    )

    with pytest.raises(ScanResultConsistencyError, match="policy findings"):
        result.seal(policy)


def test_seal_rejects_capability_that_has_no_discovered_tool() -> None:
    policy = Policy(max_risk_score=100)
    capabilities = [
        Capability(id="filesystem.read", tool="ghost", risk=10, reason="test evidence")
    ]
    result = ScanResult(
        tools=[],
        capabilities=capabilities,
        capability_graph=capability_graph_to_record(build_capability_graph(capabilities)),
        policy=policy_to_record(policy),
    )
    result.findings = evaluate_policy(capabilities, policy, result.risk_score)

    with pytest.raises(ScanResultConsistencyError, match="absent from discovered tools"):
        result.seal(policy)


def test_sealed_result_rejects_graph_drift_before_json_serialization() -> None:
    result = _sealed_result()
    assert result.capability_graph is not None
    result.capability_graph["paths"] = [
        {
            "id": "fabricated.path",
            "title": "Fabricated path",
            "severity": "LOW",
            "confidence": "high",
            "capabilities": ["filesystem.read"],
            "tools": ["reader"],
            "evidence": [],
            "message": "fabricated",
        }
    ]

    with pytest.raises(ScanResultConsistencyError, match="capability_graph"):
        result.to_dict()


def test_sealed_result_rejects_policy_or_findings_drift() -> None:
    result = _sealed_result()
    assert isinstance(result.policy, dict)
    result.policy["deny"] = ["filesystem.read"]

    with pytest.raises(ScanResultConsistencyError, match="changed after scanner construction"):
        result.to_dict()

    result = _sealed_result()
    result.findings.append(
        Finding(
            severity="HIGH",
            rule_id="fabricated.finding",
            message="Fabricated finding",
            capability="filesystem.read",
            tool="reader",
        )
    )

    with pytest.raises(ScanResultConsistencyError, match="changed after scanner construction"):
        result.to_dict()


def test_unsealed_manual_scan_result_keeps_1x_library_compatibility() -> None:
    result = ScanResult(
        capabilities=[
            Capability(
                id="filesystem.read",
                tool="manual-only",
                risk=10,
                reason="manual library construction",
            )
        ]
    )

    record = result.to_dict()

    assert record["risk_score"] == 10
    assert record["capabilities"][0]["tool"] == "manual-only"
