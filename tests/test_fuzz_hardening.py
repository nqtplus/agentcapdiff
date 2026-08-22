import json
import random
import string
from pathlib import Path

import yaml

from agentcapdiff.discovery import DiscoveryLimitError, DiscoveryLimits, discover_tools
from agentcapdiff.formats import markdown_diff_report

ALPHABET = string.ascii_letters + string.digits + "<>[](){}*_#!|`\\\n\r:/.-"


def _random_text(rng: random.Random, size: int = 80) -> str:
    return "".join(rng.choice(ALPHABET) for _ in range(size))


def test_fuzz_json_yaml_discovery_stays_bounded_and_does_not_execute(tmp_path: Path):
    rng = random.Random(20260822)
    marker = tmp_path / "must-not-exist"
    for index in range(80):
        name = _random_text(rng, 24)
        description = _random_text(rng, 80)
        payload = {
            "tools": [
                {
                    "name": name,
                    "description": description,
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "examples": [_random_text(rng, 30)]}
                        },
                    },
                }
            ],
            "never_execute": f"touch {marker}",
        }
        path = tmp_path / (f"case-{index}.json" if index % 2 == 0 else f"case-{index}.yaml")
        if path.suffix == ".json":
            path.write_text(json.dumps(payload), encoding="utf-8")
        else:
            path.write_text(yaml.safe_dump(payload), encoding="utf-8")

    try:
        tools = discover_tools(
            tmp_path,
            DiscoveryLimits(
                max_file_bytes=64_000,
                max_total_bytes=1_000_000,
                max_documents=100,
                max_depth=32,
                max_nodes_per_document=10_000,
            ),
        )
        assert len(tools) <= 80
    except DiscoveryLimitError as exc:
        assert "limit" in str(exc) or "exceeds" in str(exc)
    assert not marker.exists()


def test_fuzz_markdown_output_never_emits_raw_html_or_injected_headings():
    rng = random.Random(424242)
    for _ in range(120):
        value = "<script>" + _random_text(rng, 60) + "\n# injected"
        report = markdown_diff_report(
            {
                "base_risk_score": 0,
                "head_risk_score": 0,
                "risk_delta": 0,
                "capabilities_added": [],
                "capabilities_removed": [],
                "tools_added": [value],
                "tools_removed": [],
                "scope_changes": [],
                "scope_expansions": [],
                "head_findings": [],
            }
        )
        assert "<script>" not in report
        assert "\n# injected" not in report


def test_property_free_form_path_schema_is_never_restricted(tmp_path: Path):
    for index in range(30):
        payload = {
            "name": "read_file",
            "description": "Read a caller-selected file",
            "inputSchema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
            },
        }
        path = tmp_path / f"free-{index}.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
    tools = discover_tools(tmp_path)
    assert tools
    assert all(tool.input_schema is not None for tool in tools)
