import json
from pathlib import Path

import pytest

from agentcapdiff.cli import main
from agentcapdiff.discovery import DiscoveryLimitError, discover_tools


@pytest.mark.parametrize("filename", ["tools.toml", "tools.txt", "tools.json.bak", "tools"])
def test_explicit_unsupported_suffix_fails_closed(tmp_path: Path, filename: str) -> None:
    path = tmp_path / filename
    path.write_text('{"name":"runner"}', encoding="utf-8")

    with pytest.raises(DiscoveryLimitError, match="must use a supported suffix"):
        discover_tools(path)


def test_explicit_supported_suffix_is_case_insensitive(tmp_path: Path) -> None:
    path = tmp_path / "tools.JSON"
    path.write_text(
        json.dumps(
            {
                "name": "fetch_url",
                "description": "HTTP fetch",
                "inputSchema": {"type": "object"},
            }
        ),
        encoding="utf-8",
    )

    tools = discover_tools(path)

    assert [tool.name for tool in tools] == ["fetch_url"]


def test_directory_scan_still_ignores_unsupported_suffixes(tmp_path: Path) -> None:
    (tmp_path / "notes.toml").write_text("not = 'tool metadata'\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("ignored", encoding="utf-8")
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


def test_cli_scan_unsupported_explicit_suffix_returns_controlled_error(
    tmp_path: Path,
    capsys,
) -> None:
    path = tmp_path / "tools.toml"
    path.write_text("name = 'runner'\n", encoding="utf-8")

    assert main(["scan", str(path), "--fail-on", "never"]) == 3
    stderr = capsys.readouterr().err
    assert "unsafe or invalid scan input/policy" in stderr
    assert "must use a supported suffix" in stderr
    assert "Traceback" not in stderr


def test_cli_snapshot_unsupported_explicit_suffix_does_not_write(
    tmp_path: Path,
    capsys,
) -> None:
    path = tmp_path / "tools.txt"
    path.write_text("ignored", encoding="utf-8")
    output = tmp_path / "snapshot.json"

    assert main(["snapshot", str(path), "--output", str(output)]) == 3
    stderr = capsys.readouterr().err
    assert "must use a supported suffix" in stderr
    assert not output.exists()
