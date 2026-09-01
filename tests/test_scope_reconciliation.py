import json
from pathlib import Path

from agentcapdiff.diffing import compare_snapshots, snapshot_payload
from agentcapdiff.models import Capability, ScopeEvidence
from agentcapdiff.scanner import scan
from agentcapdiff.scope_reconcile import reconcile_capability_scopes
from agentcapdiff.snapshotio import load_snapshot


def _cap(
    scope: ScopeEvidence,
    *,
    source: str,
) -> Capability:
    return Capability(
        id="filesystem.read",
        tool="read_file",
        risk=10,
        reason="test evidence",
        source=source,
        scope=scope,
    )


def test_restricted_plus_unknown_preserves_uncertainty() -> None:
    reconciled = reconcile_capability_scopes(
        [
            _cap(ScopeEvidence("restricted", ("./reports/**",), "finite"), source="a.json"),
            _cap(ScopeEvidence("unknown", (), "dynamic"), source="b.json"),
        ]
    )

    assert {cap.source for cap in reconciled} == {"a.json", "b.json"}
    assert {cap.scope.kind for cap in reconciled} == {"unknown"}
    assert {cap.scope.values for cap in reconciled} == {()}


def test_broad_scope_dominates_duplicate_group() -> None:
    reconciled = reconcile_capability_scopes(
        [
            _cap(ScopeEvidence("restricted", ("./reports/**",), "finite"), source="a.json"),
            _cap(ScopeEvidence("broad", ("/**",), "broad"), source="b.json"),
            _cap(ScopeEvidence("unknown", (), "dynamic"), source="c.json"),
        ]
    )

    assert {cap.scope.kind for cap in reconciled} == {"broad"}
    assert {cap.scope.values for cap in reconciled} == {("/**",)}


def test_restricted_scopes_merge_to_conservative_union_and_are_order_independent() -> None:
    capabilities = [
        _cap(ScopeEvidence("restricted", ("./reports/**",), "finite"), source="a.json"),
        _cap(ScopeEvidence("restricted", ("./exports/**",), "finite"), source="b.json"),
    ]

    forward = reconcile_capability_scopes(capabilities)
    reverse = reconcile_capability_scopes(list(reversed(capabilities)))
    expected = ("./exports/**", "./reports/**")

    assert {cap.scope.values for cap in forward} == {expected}
    assert {cap.scope.values for cap in reverse} == {expected}


def _write_duplicate_tool_fixture(root: Path) -> None:
    restricted = {
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read a file from the project workspace",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {
                                "type": "string",
                                "enum": ["./reports/**"],
                            }
                        },
                    },
                },
            }
        ]
    }
    ambiguous = {
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read a file from the project workspace",
                    "parameters": {
                        "type": "object",
                        "properties": {"path": {"type": "string"}},
                    },
                },
            }
        ]
    }
    (root / "a.json").write_text(json.dumps(restricted), encoding="utf-8")
    (root / "b.json").write_text(json.dumps(ambiguous), encoding="utf-8")


def test_scanner_snapshot_round_trip_accepts_duplicate_tool_scope_conflict(
    tmp_path: Path,
) -> None:
    _write_duplicate_tool_fixture(tmp_path)
    result = scan(tmp_path)

    capabilities = [
        cap
        for cap in result.capabilities
        if cap.id == "filesystem.read" and cap.tool == "read_file"
    ]
    assert len(capabilities) == 2
    assert {Path(cap.source).name for cap in capabilities} == {"a.json", "b.json"}
    assert {cap.scope.kind for cap in capabilities} == {"unknown"}

    payload = snapshot_payload(result)
    base = tmp_path / "base-snapshot.json"
    head = tmp_path / "head-snapshot.json"
    base.write_text(json.dumps(payload), encoding="utf-8")
    head.write_text(json.dumps(payload), encoding="utf-8")

    loaded = load_snapshot(base)
    assert loaded["capabilities"]
    diff = compare_snapshots(base, head)
    assert diff["capabilities_added"] == []
    assert diff["capabilities_removed"] == []
    assert diff["scope_changes"] == []
