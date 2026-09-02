import json
from pathlib import Path

from agentcapdiff.discovery import discover_tools


def _write_tool(path: Path, name: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "name": name,
                "description": "HTTP fetch",
                "inputSchema": {"type": "object"},
            }
        ),
        encoding="utf-8",
    )


def test_explicit_scan_root_named_build_is_not_ignored(tmp_path: Path) -> None:
    root = tmp_path / "build"
    root.mkdir()
    _write_tool(root / "tools.json", "root_tool")

    tools = discover_tools(root)

    assert [tool.name for tool in tools] == ["root_tool"]


def test_scan_root_below_ignored_named_ancestor_is_not_ignored(tmp_path: Path) -> None:
    root = tmp_path / "dist" / "agent"
    root.mkdir(parents=True)
    _write_tool(root / "tools.json", "nested_root_tool")

    tools = discover_tools(root)

    assert [tool.name for tool in tools] == ["nested_root_tool"]


def test_explicit_file_below_node_modules_is_not_ignored(tmp_path: Path) -> None:
    path = tmp_path / "node_modules" / "tools.json"
    _write_tool(path, "explicit_tool")

    tools = discover_tools(path)

    assert [tool.name for tool in tools] == ["explicit_tool"]


def test_ignored_directory_inside_scan_root_remains_ignored(tmp_path: Path) -> None:
    root = tmp_path / "agent"
    root.mkdir()
    _write_tool(root / "tools.json", "visible_tool")
    _write_tool(root / "node_modules" / "hidden.json", "ignored_tool")
    _write_tool(root / "build" / "hidden.json", "ignored_build_tool")

    tools = discover_tools(root)

    assert [tool.name for tool in tools] == ["visible_tool"]


def test_nested_nonignored_directory_still_discovers_tools(tmp_path: Path) -> None:
    root = tmp_path / "agent"
    root.mkdir()
    _write_tool(root / "config" / "tools.json", "nested_tool")

    tools = discover_tools(root)

    assert [tool.name for tool in tools] == ["nested_tool"]
