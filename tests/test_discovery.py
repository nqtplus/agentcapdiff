import json
from pathlib import Path

from agentcapdiff.discovery import discover_tools


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
