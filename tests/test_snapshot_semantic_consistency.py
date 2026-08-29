import copy
import json
from pathlib import Path

import pytest

from agentcapdiff.diffing import compare_snapshots, snapshot_payload
from agentcapdiff.graph import build_capability_graph, capability_graph_to_record
from agentcapdiff.models import Capability, Finding, ScanResult, ScopeEvidence, ToolRecord
from agentcapdiff.snapshotio import SnapshotArtifactError, load_snapshot


def _capability(
    capability_id: str,
    tool: str,
    risk: int,
    *,
    source: str,
    scope: ScopeEvidence | None = None,
) -> Capability:
    return Capability(
        id=capability_id,
        tool=tool,
        risk=risk,
        reason="static test evidence",
        source=source,
        scope=scope or ScopeEvidence(),
        confidence="medium",
    )


def _valid_payload() -> dict:
    capabilities = [
        _capability("secrets.access", "read_secret", 35, source="secrets.json"),
        _capability(
            "network.external",
            "fetch_url",
            15,
            source="network.json",
            scope=ScopeEvidence(
                kind="restricted",
                values=("api.example.com",),
                reason="Static input exposes a finite destination constraint.",
            ),
        ),
    ]
    result = ScanResult(
        tools=[
            ToolRecord(name="read_secret", source="secrets.json"),
            ToolRecord(name="fetch_url", source="network.json"),
        ],
        capabilities=capabilities,
        findings=[
            Finding(
                "MEDIUM",
                "capability.review_required",
                "Capability requires human review: network.external",
                "network.external",
                "fetch_url",
                "network.json",
            )
        ],
        capability_graph=capability_graph_to_record(build_capability_graph(capabilities)),
    )
    return snapshot_payload(result)


def _write(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def _assert_rejected(tmp_path: Path, payload: dict, match: str) -> None:
    path = tmp_path / "snapshot.json"
    _write(path, payload)
    with pytest.raises(SnapshotArtifactError, match=match):
        load_snapshot(path)


def test_current_snapshot_semantics_are_accepted(tmp_path: Path) -> None:
    payload = _valid_payload()
    path = tmp_path / "snapshot.json"
    _write(path, payload)

    loaded = load_snapshot(path)
    assert loaded["capabilities"] == ["network.external", "secrets.access"]
    assert loaded["risk_score"] == 50
    assert loaded["max_severity"] == "MEDIUM"


def test_capabilities_must_match_capability_records(tmp_path: Path) -> None:
    payload = _valid_payload()
    payload["capabilities"] = ["network.external"]
    payload.pop("capability_fingerprint")
    _assert_rejected(tmp_path, payload, "capabilities do not match capability_records")


def test_capability_record_tool_must_exist_even_when_tools_list_is_empty(tmp_path: Path) -> None:
    payload = _valid_payload()
    payload["tools"] = []
    _assert_rejected(tmp_path, payload, "capability_records reference tools absent from tools")


def test_risk_score_must_match_capability_records(tmp_path: Path) -> None:
    payload = _valid_payload()
    payload["risk_score"] = 1
    _assert_rejected(tmp_path, payload, "risk_score does not match capability_records")


def test_scopes_must_match_capability_records(tmp_path: Path) -> None:
    payload = _valid_payload()
    payload["scopes"][0]["kind"] = "broad"
    payload["scopes"][0]["values"] = ["*"]
    _assert_rejected(tmp_path, payload, "scopes do not match capability_records")


def test_scope_reference_to_absent_capability_fails_without_records(tmp_path: Path) -> None:
    payload = {
        "schema": 1,
        "risk_score": 0,
        "max_severity": "INFO",
        "capabilities": [],
        "tools": [],
        "findings": [],
        "scopes": [
            {
                "capability": "network.external",
                "tool": "fetch_url",
                "kind": "restricted",
                "values": ["api.example.com"],
                "reason": "crafted contradiction",
            }
        ],
    }
    _assert_rejected(tmp_path, payload, "references capability absent from capabilities")


def test_graph_must_match_capability_records(tmp_path: Path) -> None:
    payload = _valid_payload()
    payload["capability_graph"]["paths"][0]["severity"] = "HIGH"
    _assert_rejected(tmp_path, payload, "capability_graph does not match capability_records")


def test_finding_reference_to_absent_tool_fails_with_empty_tools(tmp_path: Path) -> None:
    payload = {
        "schema": 1,
        "risk_score": 0,
        "max_severity": "HIGH",
        "capabilities": [],
        "tools": [],
        "findings": [
            {
                "severity": "HIGH",
                "rule_id": "crafted.finding",
                "message": "crafted contradiction",
                "capability": None,
                "tool": "shell",
            }
        ],
    }
    _assert_rejected(tmp_path, payload, "references tool absent from tools")


def test_max_severity_must_match_findings(tmp_path: Path) -> None:
    payload = _valid_payload()
    payload["max_severity"] = "INFO"
    _assert_rejected(tmp_path, payload, "max_severity does not match findings")


def test_conflicting_capability_record_identity_fails_closed(tmp_path: Path) -> None:
    payload = _valid_payload()
    duplicate = copy.deepcopy(payload["capability_records"][0])
    duplicate["risk"] += 1
    payload["capability_records"].append(duplicate)
    _assert_rejected(tmp_path, payload, "conflicting records for identity")


def test_additive_unknown_fields_remain_ignorable_when_known_semantics_match(
    tmp_path: Path,
) -> None:
    payload = _valid_payload()
    payload["capability_records"][0]["future_evidence"] = {"ignored": True}
    payload["capability_graph"]["future_graph_field"] = {"ignored": True}
    payload["capability_graph"]["paths"][0]["future_path_field"] = ["ignored"]
    payload["future_top_level"] = {"ignored": True}
    path = tmp_path / "snapshot.json"
    _write(path, payload)

    loaded = load_snapshot(path)
    assert loaded["future_top_level"] == {"ignored": True}


def test_legacy_snapshot_without_additive_records_remains_readable(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    legacy = {
        "schema": 1,
        "risk_score": 10,
        "max_severity": "INFO",
        "capabilities": ["filesystem.read"],
        "tools": ["read_file"],
        "findings": [],
    }
    _write(base, legacy)
    _write(head, {**legacy, "future_additive": {"ignored": True}})

    diff = compare_snapshots(base, head)
    assert diff["capabilities_added"] == []
    assert diff["capabilities_removed"] == []
    assert diff["risk_delta"] == 0
