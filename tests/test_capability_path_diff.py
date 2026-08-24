from pathlib import Path

from agentcapdiff.diffing import compare_snapshots, write_snapshot
from agentcapdiff.formats import markdown_diff_report
from agentcapdiff.graph import build_capability_graph, capability_graph_to_record
from agentcapdiff.models import Capability, ScanResult, ScopeEvidence


def _cap(capability_id: str, tool: str, risk: int, scope: str = "unknown") -> Capability:
    return Capability(
        id=capability_id,
        tool=tool,
        risk=risk,
        reason="test evidence",
        scope=ScopeEvidence(kind=scope),
    )


def _result(capabilities: list[Capability]) -> ScanResult:
    graph = build_capability_graph(capabilities)
    return ScanResult(
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


def test_old_snapshot_without_graph_remains_readable(tmp_path: Path):
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(
        '{"schema":1,"capabilities":[],"tools":[],"risk_score":0,"findings":[]}',
        encoding="utf-8",
    )
    write_snapshot(_result([]), head)

    diff = compare_snapshots(base, head)
    assert diff["paths_added"] == []
    assert diff["paths_removed"] == []
