from pathlib import Path

from agentcapdiff.diffing import compare_snapshots, write_snapshot
from agentcapdiff.formats import markdown_diff_report
from agentcapdiff.graph import build_capability_graph, capability_graph_to_record
from agentcapdiff.models import Capability, ScanResult, ScopeEvidence, ToolRecord


def _cap(
    capability_id: str,
    tool: str,
    risk: int,
    scope: str = "unknown",
    *,
    confidence: str = "medium",
) -> Capability:
    return Capability(
        id=capability_id,
        tool=tool,
        risk=risk,
        reason="test evidence",
        scope=ScopeEvidence(kind=scope),
        confidence=confidence,
    )


def _result(capabilities: list[Capability]) -> ScanResult:
    graph = build_capability_graph(capabilities)
    return ScanResult(
        tools=[ToolRecord(name) for name in sorted({cap.tool for cap in capabilities})],
        capabilities=capabilities,
        capability_graph=capability_graph_to_record(graph),
    )


def test_snapshot_diff_surfaces_new_possible_path(tmp_path: Path):
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    write_snapshot(_result([_cap("secrets.access", "read_secret", 35)]), base)
    write_snapshot(
        _result(
            [
                _cap("secrets.access", "read_secret", 35),
                _cap("network.external", "fetch_url", 15, scope="unknown"),
            ]
        ),
        head,
    )

    diff = compare_snapshots(base, head)
    assert [path["id"] for path in diff["paths_added"]] == [
        "possible.secrets_network_exfiltration"
    ]

    markdown = markdown_diff_report(diff)
    assert "### New possible capability paths" in markdown
    assert "Possible credential/data exfiltration path" in markdown
    assert "runtime reachability/exploitability is not established" in markdown


def test_existing_path_severity_and_uncertainty_escalation_is_explicit(tmp_path: Path):
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    write_snapshot(
        _result(
            [
                _cap("secrets.access", "read_secret", 35, confidence="high"),
                _cap(
                    "network.external",
                    "fetch_url",
                    15,
                    scope="restricted",
                    confidence="high",
                ),
            ]
        ),
        base,
    )
    write_snapshot(
        _result(
            [
                _cap("secrets.access", "read_secret", 35, confidence="high"),
                _cap(
                    "network.external",
                    "fetch_url",
                    15,
                    scope="unknown",
                    confidence="high",
                ),
            ]
        ),
        head,
    )

    diff = compare_snapshots(base, head)
    assert diff["paths_added"] == []
    assert diff["paths_removed"] == []
    assert [item["id"] for item in diff["path_changes"]] == [
        "possible.secrets_network_exfiltration"
    ]
    escalation = diff["path_escalations"][0]
    assert escalation["before"]["severity"] == "MEDIUM"
    assert escalation["after"]["severity"] == "HIGH"
    assert escalation["before"]["confidence"] == "high"
    assert escalation["after"]["confidence"] == "low"
    assert set(escalation["reasons"]) == {
        "severity_increased",
        "confidence_decreased",
    }

    markdown = markdown_diff_report(diff)
    assert "### Changed possible capability paths" in markdown
    assert "PATH RISK/UNCERTAINTY INCREASED" in markdown
    assert "MEDIUM → HIGH" in markdown
    assert "high → low" in markdown


def test_existing_path_tool_expansion_is_review_required(tmp_path: Path):
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base_caps = [
        _cap("secrets.access", "read_secret", 35),
        _cap("network.external", "fetch_primary", 15, scope="restricted"),
    ]
    head_caps = [
        *base_caps,
        _cap("network.external", "fetch_secondary", 15, scope="restricted"),
    ]
    write_snapshot(_result(base_caps), base)
    write_snapshot(_result(head_caps), head)

    diff = compare_snapshots(base, head)
    assert diff["paths_added"] == []
    assert diff["capabilities_added"] == []
    assert diff["tools_added"] == ["fetch_secondary"]
    assert [item["reasons"] for item in diff["path_escalations"]] == [["tools_expanded"]]
    assert diff["path_changes"][0]["after"]["tools"] == [
        "fetch_primary",
        "fetch_secondary",
        "read_secret",
    ]

    markdown = markdown_diff_report(diff)
    assert "PATH RISK/UNCERTAINTY INCREASED" in markdown
    assert "fetch\\_secondary" in markdown


def test_reordered_capability_records_do_not_create_path_change(tmp_path: Path):
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    capabilities = [
        _cap("secrets.access", "read_secret", 35),
        _cap("network.external", "fetch_url", 15, scope="restricted"),
    ]
    write_snapshot(_result(capabilities), base)
    write_snapshot(_result(list(reversed(capabilities))), head)

    diff = compare_snapshots(base, head)
    assert diff["path_changes"] == []
    assert diff["path_escalations"] == []


def test_old_snapshot_without_graph_remains_readable(tmp_path: Path):
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(
        '{"schema": 1, "risk_score": 0, "capabilities": [], "tools": [], "findings": []}',
        encoding="utf-8",
    )
    write_snapshot(_result([]), head)

    diff = compare_snapshots(base, head)
    assert diff["paths_added"] == []
    assert diff["paths_removed"] == []
    assert diff["path_changes"] == []
    assert diff["path_escalations"] == []
