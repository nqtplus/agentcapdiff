import json
import socket
from pathlib import Path

from agentcapdiff.cli import main
from agentcapdiff.scanner import scan


def test_scan_does_not_make_network_calls_from_discovered_url(tmp_path: Path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("network access attempted during static scan")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    (tmp_path / "tool.json").write_text(
        json.dumps(
            {
                "name": "fetch_url",
                "description": "Fetch any arbitrary URL",
                "inputSchema": {
                    "type": "object",
                    "properties": {"url": {"const": "https://example.invalid/test"}},
                },
            }
        ),
        encoding="utf-8",
    )
    result = scan(tmp_path)
    assert any(cap.id == "network.external" for cap in result.capabilities)


def test_cli_writes_only_to_explicit_output_path(tmp_path: Path):
    source = tmp_path / "input"
    source.mkdir()
    (source / "tool.json").write_text(
        json.dumps(
            {
                "name": "read_file",
                "description": "Read a caller-selected file",
                "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ),
        encoding="utf-8",
    )
    before = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    output = tmp_path / "explicit.json"
    assert main(["scan", str(source), "--format", "json", "--output", str(output), "--fail-on", "never"]) == 0
    after = {p.relative_to(tmp_path) for p in tmp_path.rglob("*")}
    assert output.exists()
    assert after - before == {Path("explicit.json")}


def test_scope_output_escapes_untrusted_values_in_markdown(tmp_path: Path):
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    payload = {
        "risk_score": 10,
        "capabilities": ["filesystem.read"],
        "tools": ["read_file"],
        "scopes": [],
    }
    base.write_text(json.dumps(payload), encoding="utf-8")
    head.write_text(
        json.dumps(
            {
                **payload,
                "scopes": [
                    {
                        "capability": "filesystem.read",
                        "tool": "read_file",
                        "kind": "restricted",
                        "values": ["<script>\n# injected"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "diff.md"
    assert main(["diff", str(base), str(head), "--format", "markdown", "--output", str(output)]) == 0
    report = output.read_text(encoding="utf-8")
    assert "<script>" not in report
    assert "\n# injected" not in report
