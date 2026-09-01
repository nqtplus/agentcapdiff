import json
from pathlib import Path

import pytest

from agentcapdiff.diffing import snapshot_payload
from agentcapdiff.formats import sarif_report, text_report
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


def test_reseal_is_idempotent_only_for_the_same_effective_policy() -> None:
    policy = Policy(max_risk_score=100)
    result = _sealed_result(policy)

    result.seal(policy)

    with pytest.raises(ScanResultConsistencyError, match="effective runtime policy"):
        result.seal(Policy(deny={"filesystem.read"}, max_risk_score=100))


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


@pytest.mark.parametrize("serializer", [text_report, sarif_report, snapshot_payload])
def test_sealed_result_rejects_drift_at_library_output_boundaries(serializer) -> None:
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
        serializer(result)


@pytest.mark.parametrize("serializer", [lambda result: result.to_dict(), snapshot_payload])
def test_sealed_mapping_outputs_are_detached_from_internal_state(serializer) -> None:
    result = _sealed_result()
    output = serializer(result)
    assert isinstance(output["policy"], dict)
    assert isinstance(output["capability_graph"], dict)
    assert isinstance(result.policy, dict)
    assert isinstance(result.capability_graph, dict)

    output["policy"]["deny"] = ["filesystem.read"]
    output["capability_graph"]["paths"] = [
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

    assert result.policy["deny"] == []
    assert result.capability_graph["paths"] == []
    result.assert_consistent()


def test_unsealed_manual_scan_result_keeps_1x_library_compatibility() -> None:
    graph = {"schema_version": "1", "nodes": [], "edges": [], "paths": []}
    policy = {"deny": []}
    result = ScanResult(
        capabilities=[
            Capability(
                id="filesystem.read",
                tool="manual-only",
                risk=10,
                reason="manual library construction",
            )
        ],
        capability_graph=graph,
        policy=policy,
    )

    record = result.to_dict()
    snapshot = snapshot_payload(result)

    assert record["risk_score"] == 10
    assert record["capabilities"][0]["tool"] == "manual-only"
    assert record["capability_graph"] is graph
    assert record["policy"] is policy
    assert snapshot["capability_graph"] is graph
    assert snapshot["policy"] is policy
    assert "AgentCapDiff" in text_report(result)
    assert '"runs"' in sarif_report(result)
