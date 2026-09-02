import json
from pathlib import Path

import pytest

from agentcapdiff.cli import main
from agentcapdiff.discovery import DiscoveryLimitError, discover_tools


def test_explicit_malformed_json_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "tools.json"
    path.write_text('{"tools": [', encoding="utf-8")

    with pytest.raises(DiscoveryLimitError, match="explicit discovery input is malformed"):
        discover_tools(path)


def test_explicit_malformed_yaml_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "tools.yaml"
    path.write_text("tools: [\n", encoding="utf-8")

    with pytest.raises(DiscoveryLimitError, match="explicit discovery input is malformed"):
        discover_tools(path)


def test_explicit_invalid_utf8_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "tools.json"
    path.write_bytes(b"\xff\xfe\x00")

    with pytest.raises(DiscoveryLimitError, match="explicit discovery input is malformed"):
        discover_tools(path)


def test_directory_scan_still_tolerates_unrelated_malformed_documents(tmp_path: Path) -> None:
    (tmp_path / "broken.json").write_text('{"not": [', encoding="utf-8")
    (tmp_path / "tools.json").write_text(
        json.dumps(
            {
                "name": "fetch_url",
                "description": "HTTP fetch",
                "inputSchema": {"type": "object"},
            }
        ),
        encoding="utf-8",
    )

    tools = discover_tools(tmp_path)

    assert [tool.name for tool in tools] == ["fetch_url"]


def test_cli_scan_reports_explicit_parse_failure_without_traceback(
    tmp_path: Path,
    capsys,
) -> None:
    path = tmp_path / "tools.json"
    path.write_text('{"tools": [', encoding="utf-8")

    assert main(["scan", str(path), "--fail-on", "never"]) == 3
    captured = capsys.readouterr()
    assert "unsafe or invalid scan input/policy" in captured.err
    assert "explicit discovery input is malformed" in captured.err
    assert "Traceback" not in captured.err


def test_cli_snapshot_does_not_write_for_explicit_parse_failure(
    tmp_path: Path,
    capsys,
) -> None:
    path = tmp_path / "tools.yaml"
    path.write_text("tools: [\n", encoding="utf-8")
    output = tmp_path / "snapshot.json"

    assert main(["snapshot", str(path), "--output", str(output)]) == 3
    captured = capsys.readouterr()
    assert "unsafe or invalid scan input/policy" in captured.err
    assert "explicit discovery input is malformed" in captured.err
    assert not output.exists()
