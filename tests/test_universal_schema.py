import json
from pathlib import Path

from agentcapdiff.capabilities import infer_capabilities
from agentcapdiff.discovery import discover_tools
from agentcapdiff.models import Capability, ScopeEvidence
from agentcapdiff.schema import (
    canonical_capabilities_json,
    capability_from_record,
    capability_to_record,
)


def _equivalent_tool_payloads(tmp_path: Path) -> None:
    openai = {
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read a file",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "enum": ["./reports/**"]}
                        },
                    },
                },
            }
        ]
    }
    mcp = {
        "tools": [
            {
                "name": "read_file",
                "description": "Read a file",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "enum": ["./reports/**"]}
                    },
                },
            }
        ]
    }
    (tmp_path / "openai.json").write_text(json.dumps(openai), encoding="utf-8")
    (tmp_path / "mcp.json").write_text(json.dumps(mcp), encoding="utf-8")


def test_openai_and_mcp_normalize_equivalent_privilege(tmp_path: Path):
    _equivalent_tool_payloads(tmp_path)
    tools = discover_tools(tmp_path)
    assert {tool.adapter for tool in tools} == {"openai", "mcp"}

    caps = infer_capabilities(tools)
    assert len(caps) == 2
    assert {cap.id for cap in caps} == {"filesystem.read"}
    assert {cap.risk for cap in caps} == {10}
    assert {cap.scope.kind for cap in caps} == {"restricted"}
    assert {cap.scope.values for cap in caps} == {("./reports/**",)}
    assert {cap.confidence for cap in caps} == {"medium"}
    assert {cap.evidence[0].adapter for cap in caps} == {"openai", "mcp"}


def test_schema_round_trip_is_deterministic_and_preserves_uncertainty():
    cap = Capability(
        id="network.external",
        tool="fetch_url",
        risk=15,
        reason="Can communicate with external network resources.",
        scope=ScopeEvidence(kind="unknown"),
        confidence="low",
    )
    record = capability_to_record(cap)
    restored = capability_from_record(record)

    assert restored == cap
    assert restored.scope.kind == "unknown"
    assert canonical_capabilities_json([restored]) == canonical_capabilities_json([cap])


def test_unknown_schema_scope_and_confidence_fail_conservatively():
    record = {
        "schema_version": "1",
        "id": "filesystem.read",
        "tool": "read_file",
        "risk": 10,
        "reason": "Can read local files.",
        "scope": {"kind": "framework_magic", "values": ["./safe/**"]},
        "confidence": "certain",
    }
    cap = capability_from_record(record)
    assert cap.scope.kind == "unknown"
    assert cap.scope.values == ("./safe/**",)
    assert cap.confidence == "low"
