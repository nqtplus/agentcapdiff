from pathlib import Path

import pytest

from agentcapdiff.cli import main
from agentcapdiff.discovery import DiscoveryLimitError, discover_tools


def test_explicit_json_duplicate_key_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "tools.json"
    path.write_text(
        '{"name":"runner","description":"execute shell command",'
        '"description":"benign","inputSchema":{"type":"object"}}',
        encoding="utf-8",
    )

    with pytest.raises(DiscoveryLimitError, match="ambiguous duplicate mapping keys"):
        discover_tools(path)


def test_directory_json_duplicate_key_is_not_tolerantly_skipped(tmp_path: Path) -> None:
    (tmp_path / "ambiguous.json").write_text(
        '{"name":"runner","inputSchema":{"type":"object"},'
        '"inputSchema":{"type":"object","properties":{}}}',
        encoding="utf-8",
    )

    with pytest.raises(DiscoveryLimitError, match="ambiguous duplicate mapping keys"):
        discover_tools(tmp_path)


def test_nested_json_schema_duplicate_key_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "tools.json"
    path.write_text(
        '{"name":"runner","inputSchema":{"type":"object","properties":'
        '{"command":{"type":"string"}},"properties":{}}}',
        encoding="utf-8",
    )

    with pytest.raises(DiscoveryLimitError, match="ambiguous duplicate mapping keys"):
        discover_tools(path)


def test_unicode_escape_equivalent_json_key_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "tools.json"
    path.write_text(
        '{"name":"runner","\\u006eame":"other",'
        '"inputSchema":{"type":"object"}}',
        encoding="utf-8",
    )

    with pytest.raises(DiscoveryLimitError, match="ambiguous duplicate mapping keys"):
        discover_tools(path)


def test_directory_yaml_duplicate_key_is_not_tolerantly_skipped(tmp_path: Path) -> None:
    (tmp_path / "ambiguous.yaml").write_text(
        "name: runner\n"
        "description: execute shell command\n"
        "description: benign\n"
        "inputSchema: {type: object}\n",
        encoding="utf-8",
    )

    with pytest.raises(DiscoveryLimitError, match="ambiguous duplicate mapping keys"):
        discover_tools(tmp_path)


def test_yaml_merge_with_explicit_override_remains_valid(tmp_path: Path) -> None:
    path = tmp_path / "tools.yaml"
    path.write_text(
        "defaults: &defaults\n"
        "  description: default description\n"
        "tool:\n"
        "  <<: *defaults\n"
        "  name: fetch_url\n"
        "  description: HTTP fetch\n"
        "  inputSchema: {type: object}\n",
        encoding="utf-8",
    )

    tools = discover_tools(path)

    assert len(tools) == 1
    assert tools[0].name == "fetch_url"
    assert tools[0].description == "HTTP fetch"


def test_cli_directory_scan_duplicate_key_fails_closed(tmp_path: Path, capsys) -> None:
    (tmp_path / "ambiguous.json").write_text(
        '{"name":"runner","description":"shell command",'
        '"description":"helper","inputSchema":{"type":"object"}}',
        encoding="utf-8",
    )

    assert main(["scan", str(tmp_path), "--fail-on", "never"]) == 3
    stderr = capsys.readouterr().err
    assert "unsafe or invalid scan input/policy" in stderr
    assert "ambiguous duplicate mapping keys" in stderr
    assert "Traceback" not in stderr
