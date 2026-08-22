import json
from pathlib import Path

from agentcapdiff.capabilities import infer_capabilities
from agentcapdiff.diffing import compare_snapshots
from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_filesystem_scope, infer_network_scope


def _schema(property_name: str, property_schema: dict) -> dict:
    return {
        "type": "object",
        "properties": {property_name: property_schema},
    }


def test_filesystem_scope_restricted_broad_and_unknown():
    restricted = ToolRecord(
        "read_file",
        "Read a report file",
        input_schema=_schema("path", {"type": "string", "enum": ["./reports/**"]}),
    )
    broad = ToolRecord(
        "write_file",
        "Write a file",
        input_schema=_schema("path", {"type": "string", "const": "/**"}),
    )
    unknown = ToolRecord(
        "read_file",
        "Read a caller-selected path",
        input_schema=_schema("path", {"type": "string"}),
    )
    assert infer_filesystem_scope(restricted).kind == "restricted"
    assert infer_filesystem_scope(restricted).values == ("./reports/**",)
    assert infer_filesystem_scope(broad).kind == "broad"
    assert infer_filesystem_scope(unknown).kind == "unknown"


def test_filesystem_traversal_never_becomes_restricted():
    tool = ToolRecord(
        "read_file",
        input_schema=_schema("path", {"enum": ["../secrets/**"]}),
    )
    scope = infer_filesystem_scope(tool)
    assert scope.kind == "unknown"
    assert scope.values == ()


def test_network_scope_exact_wildcard_broad_and_unknown():
    exact = ToolRecord(
        "fetch_url",
        input_schema=_schema("url", {"enum": ["https://api.example.com/v1"]}),
    )
    wildcard = ToolRecord(
        "fetch_web",
        input_schema=_schema("domain", {"enum": ["*.example.com"]}),
    )
    broad = ToolRecord("fetch_url", "Fetch any arbitrary URL")
    unknown = ToolRecord(
        "fetch_url",
        input_schema=_schema("url", {"type": "string", "format": "uri"}),
    )
    assert infer_network_scope(exact).kind == "restricted"
    assert infer_network_scope(exact).values == ("https://api.example.com/v1",)
    assert infer_network_scope(wildcard).kind == "restricted"
    assert infer_network_scope(wildcard).values == ("*.example.com",)
    assert infer_network_scope(broad).kind == "broad"
    assert infer_network_scope(unknown).kind == "unknown"


def test_capability_ids_stay_stable_when_scope_is_added():
    tool = ToolRecord(
        "read_file",
        input_schema=_schema("path", {"const": "./reports/**"}),
    )
    caps = infer_capabilities([tool])
    assert [cap.id for cap in caps] == ["filesystem.read"]
    assert caps[0].scope.kind == "restricted"


def test_scope_diff_reports_restricted_to_broad_expansion(tmp_path: Path):
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    common = {
        "risk_score": 10,
        "capabilities": ["filesystem.read"],
        "tools": ["read_file"],
    }
    base.write_text(
        json.dumps(
            {
                **common,
                "scopes": [
                    {
                        "capability": "filesystem.read",
                        "tool": "read_file",
                        "kind": "restricted",
                        "values": ["./reports/**"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    head.write_text(
        json.dumps(
            {
                **common,
                "scopes": [
                    {
                        "capability": "filesystem.read",
                        "tool": "read_file",
                        "kind": "broad",
                        "values": ["/**"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    diff = compare_snapshots(base, head)
    assert len(diff["scope_changes"]) == 1
    assert len(diff["scope_expansions"]) == 1
    assert diff["scope_expansions"][0]["before"]["values"] == ["./reports/**"]
    assert diff["scope_expansions"][0]["after"]["values"] == ["/**"]


def test_unknown_to_broad_is_change_but_not_claimed_as_proven_expansion(tmp_path: Path):
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    common = {"risk_score": 15, "capabilities": ["network.external"], "tools": ["fetch_url"]}
    base.write_text(
        json.dumps(
            {
                **common,
                "scopes": [
                    {
                        "capability": "network.external",
                        "tool": "fetch_url",
                        "kind": "unknown",
                        "values": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    head.write_text(
        json.dumps(
            {
                **common,
                "scopes": [
                    {
                        "capability": "network.external",
                        "tool": "fetch_url",
                        "kind": "broad",
                        "values": ["*"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    diff = compare_snapshots(base, head)
    assert len(diff["scope_changes"]) == 1
    assert diff["scope_expansions"] == []
