import json
from pathlib import Path

from agentcapdiff.capabilities import infer_capabilities
from agentcapdiff.discovery import discover_tools
from agentcapdiff.models import ToolRecord


def _capabilities(tool: ToolRecord):
    return {cap.id: cap for cap in infer_capabilities([tool])}


def test_schema_only_shell_command_is_not_hidden_by_benign_name():
    tool = ToolRecord(
        name="task_worker",
        description="Process a task",
        input_schema={
            "type": "object",
            "properties": {"shellCommand": {"type": "string"}},
        },
        adapter="mcp",
    )

    capability = _capabilities(tool)["shell.execute"]

    assert capability.risk == 35
    assert capability.confidence == "low"
    assert "schema signal" in capability.evidence[0].signal
    assert "property:shell_command" in capability.evidence[0].signal


def test_schema_only_secret_input_is_preserved_with_low_confidence():
    tool = ToolRecord(
        name="session_helper",
        description="Prepare a session",
        input_schema={
            "type": "object",
            "properties": {"apiToken": {"type": "string"}},
        },
        adapter="openai-agents",
    )

    capability = _capabilities(tool)["secrets.access"]

    assert capability.risk == 35
    assert capability.confidence == "low"
    assert "property:api_token" in capability.evidence[0].signal


def test_schema_path_and_payload_preserve_filesystem_write_power():
    tool = ToolRecord(
        name="document_helper",
        description="Process a document",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "content": {"type": "string"},
            },
        },
        adapter="claude",
    )

    capabilities = _capabilities(tool)

    assert "filesystem.write" in capabilities
    assert "filesystem.read" not in capabilities
    assert capabilities["filesystem.write"].confidence == "low"


def test_action_enum_can_preserve_hidden_filesystem_mutation():
    tool = ToolRecord(
        name="file_helper",
        description="Handle a local item",
        input_schema={
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "operation": {"type": "string", "enum": ["delete"]},
            },
        },
        adapter="mcp",
    )

    capabilities = _capabilities(tool)

    assert "filesystem.write" in capabilities
    assert "filesystem.read" not in capabilities
    assert "action:path+filesystem-mutation" in capabilities["filesystem.write"].evidence[0].signal


def test_action_enum_can_preserve_hidden_github_mutation():
    tool = ToolRecord(
        name="repo_helper",
        description="Handle repository metadata",
        input_schema={
            "type": "object",
            "properties": {
                "repository": {"type": "string"},
                "operation": {"type": "string", "enum": ["merge"]},
            },
        },
        adapter="generic",
    )

    capability = _capabilities(tool)["github.write"]

    assert capability.confidence == "low"
    assert "action:repository+mutation" in capability.evidence[0].signal


def test_bare_url_parameter_is_not_automatically_treated_as_network_access():
    tool = ToolRecord(
        name="normalizer",
        description="Normalize a string",
        input_schema={
            "type": "object",
            "properties": {"url": {"type": "string"}},
        },
        adapter="mcp",
    )

    assert "network.external" not in _capabilities(tool)


def test_duplicate_tool_shapes_merge_schema_instead_of_last_writer_wins(tmp_path: Path):
    payload = {
        "tools": [
            {
                "type": "tool",
                "name": "task_worker",
                "description": "Process a task",
            },
            {
                "name": "task_worker",
                "description": "",
                "inputSchema": {
                    "type": "object",
                    "properties": {"command": {"type": "string"}},
                },
            },
        ]
    }
    path = tmp_path / "tools.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    tools = discover_tools(path)

    assert len(tools) == 1
    assert tools[0].name == "task_worker"
    assert tools[0].adapter == "generic"
    assert tools[0].input_schema is not None
    capability = _capabilities(tools[0])["shell.execute"]
    assert capability.confidence == "low"
