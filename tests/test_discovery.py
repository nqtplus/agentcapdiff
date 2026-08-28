import json
from pathlib import Path

import pytest

from agentcapdiff.discovery import DiscoveryLimitError, DiscoveryLimits, discover_tools


def test_discovers_openai_and_mcp_tools(tmp_path: Path):
    payload = {
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read a file",
                },
            }
        ]
    }
    (tmp_path / "tools.json").write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / "mcp.yaml").write_text(
        "tools:\n"
        "  - name: fetch_url\n"
        "    description: HTTP fetch\n"
        "    inputSchema: {type: object}\n",
        encoding="utf-8",
    )
    names = {tool.name for tool in discover_tools(tmp_path)}
    assert names == {"read_file", "fetch_url"}


def test_rejects_oversized_input_with_actionable_error(tmp_path: Path):
    path = tmp_path / "huge.json"
    path.write_text('{"padding":"' + ("x" * 200) + '"}', encoding="utf-8")

    with pytest.raises(DiscoveryLimitError, match="input file exceeds"):
        discover_tools(tmp_path, DiscoveryLimits(max_file_bytes=64))


def test_rejects_excessive_nesting(tmp_path: Path):
    value: object = {"leaf": True}
    for _ in range(12):
        value = {"nested": value}
    (tmp_path / "deep.json").write_text(json.dumps(value), encoding="utf-8")

    with pytest.raises(DiscoveryLimitError, match="nesting exceeds depth limit"):
        discover_tools(tmp_path, DiscoveryLimits(max_depth=5))


def test_parser_recursion_is_reported_as_limit_error(tmp_path: Path):
    path = tmp_path / "parser-deep.json"
    path.write_text("[" * 5_000 + "0" + "]" * 5_000, encoding="utf-8")

    with pytest.raises(DiscoveryLimitError, match="parser recursion exceeds safety limit"):
        discover_tools(tmp_path, DiscoveryLimits(max_depth=10_000))


def test_rejects_total_input_budget(tmp_path: Path):
    for index in range(3):
        (tmp_path / f"tool-{index}.json").write_text(
            json.dumps(
                {
                    "name": f"tool_{index}",
                    "description": "read_file",
                    "inputSchema": {"type": "object"},
                }
            ),
            encoding="utf-8",
        )

    with pytest.raises(DiscoveryLimitError, match="total parsed input exceeds"):
        discover_tools(
            tmp_path,
            DiscoveryLimits(max_file_bytes=1_024, max_total_bytes=120),
        )


def test_rejects_filesystem_entry_traversal_budget(tmp_path: Path):
    for index in range(5):
        (tmp_path / f"irrelevant-{index}.txt").write_text("ignored", encoding="utf-8")

    with pytest.raises(DiscoveryLimitError, match="filesystem entry traversal exceeds limit"):
        discover_tools(tmp_path, DiscoveryLimits(max_entries=4))


def test_yaml_alias_cycle_does_not_recurse_forever(tmp_path: Path):
    (tmp_path / "cycle.yaml").write_text("node: &node\n  self: *node\n", encoding="utf-8")
    assert discover_tools(tmp_path) == []


def test_refuses_symlinked_input(tmp_path: Path):
    target = tmp_path / "target.json"
    target.write_text(
        json.dumps(
            {
                "name": "read_file",
                "description": "read_file",
                "inputSchema": {"type": "object"},
            }
        ),
        encoding="utf-8",
    )
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")

    with pytest.raises(DiscoveryLimitError, match="refusing to read symlinked input"):
        discover_tools(link)


def test_refuses_symlinked_directory_scan_root(tmp_path: Path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "tool.json").write_text(
        json.dumps(
            {
                "name": "read_file",
                "description": "read_file",
                "inputSchema": {"type": "object"},
            }
        ),
        encoding="utf-8",
    )
    link = tmp_path / "linked-root"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks unavailable on this platform")

    with pytest.raises(DiscoveryLimitError, match="refusing symlinked scan root"):
        discover_tools(link)
