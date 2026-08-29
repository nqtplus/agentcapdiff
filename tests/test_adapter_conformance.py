import json
from pathlib import Path

import pytest

from agentcapdiff.capabilities import infer_capabilities
from agentcapdiff.discovery import discover_tools
from agentcapdiff.policy import Policy, evaluate_policy

PATH_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string", "enum": ["./reports/**"]}},
}
NETWORK_SCHEMA = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "enum": ["https://api.example.com/v1"]}
    },
}
DYNAMIC_PATH_SCHEMA = {
    "type": "object",
    "properties": {"path": {"type": "string"}},
}
SHELL_SCHEMA = {
    "type": "object",
    "properties": {"shellCommand": {"type": "string"}},
}


def _payload(adapter: str, name: str, description: str, schema: dict) -> dict:
    if adapter == "openai":
        return {
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": description,
                        "parameters": schema,
                    },
                }
            ]
        }
    if adapter == "openai-agents":
        return {
            "tools": [
                {
                    "name": name,
                    "description": description,
                    "params_json_schema": schema,
                    "strict_json_schema": True,
                }
            ]
        }
    if adapter == "mcp":
        return {
            "tools": [
                {
                    "name": name,
                    "description": description,
                    "inputSchema": schema,
                }
            ]
        }
    if adapter == "claude":
        return {
            "tools": [
                {
                    "name": name,
                    "description": description,
                    "input_schema": schema,
                    "strict": True,
                }
            ]
        }
    if adapter == "langchain":
        return {
            "tools": [
                {
                    "name": name,
                    "description": description,
                    "args_schema": schema,
                    "return_direct": False,
                    "response_format": "content",
                }
            ]
        }
    if adapter == "langgraph":
        return {
            "tools": [
                {
                    "framework": "langgraph",
                    "name": name,
                    "description": description,
                    "tool_call_schema": schema,
                }
            ]
        }
    if adapter == "crewai":
        return {
            "tools": [
                {
                    "name": name,
                    "description": description,
                    "args_schema": schema,
                    "result_as_answer": False,
                }
            ]
        }
    raise AssertionError(f"unknown test adapter: {adapter}")


def _scan_payload(tmp_path: Path, adapter: str, payload: dict):
    path = tmp_path / f"{adapter}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    tools = discover_tools(path)
    assert len(tools) == 1
    capabilities = infer_capabilities(tools)
    assert len(capabilities) == 1
    return tools[0], capabilities[0]


ADAPTERS = (
    "openai",
    "openai-agents",
    "mcp",
    "claude",
    "langchain",
    "langgraph",
    "crewai",
)


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_filesystem_privilege_normalizes_consistently(tmp_path: Path, adapter: str):
    tool, capability = _scan_payload(
        tmp_path,
        adapter,
        _payload(adapter, "read_file", "Read a file", PATH_SCHEMA),
    )

    assert tool.adapter == adapter
    assert capability.id == "filesystem.read"
    assert capability.risk == 10
    assert capability.scope.kind == "restricted"
    assert capability.scope.values == ("./reports/**",)
    assert capability.confidence == "medium"
    assert capability.evidence[0].adapter == adapter


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_network_privilege_normalizes_consistently(tmp_path: Path, adapter: str):
    _, capability = _scan_payload(
        tmp_path,
        adapter,
        _payload(adapter, "fetch_url", "Fetch an HTTP URL", NETWORK_SCHEMA),
    )

    assert capability.id == "network.external"
    assert capability.risk == 15
    assert capability.scope.kind == "restricted"
    assert capability.scope.values == ("https://api.example.com/v1",)


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_schema_hidden_shell_privilege_cannot_downgrade_by_adapter(
    tmp_path: Path,
    adapter: str,
):
    tool, capability = _scan_payload(
        tmp_path,
        adapter,
        _payload(adapter, "task_worker", "Process a task", SHELL_SCHEMA),
    )

    assert tool.adapter == adapter
    assert capability.id == "shell.execute"
    assert capability.risk == 35
    assert capability.confidence == "low"
    assert "property:shell_command" in capability.evidence[0].signal


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_dynamic_scope_remains_unknown(tmp_path: Path, adapter: str):
    _, capability = _scan_payload(
        tmp_path,
        adapter,
        _payload(adapter, "read_file", "Read a file", DYNAMIC_PATH_SCHEMA),
    )

    assert capability.id == "filesystem.read"
    assert capability.scope.kind == "unknown"
    assert capability.scope.values == ()


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_adapter_cannot_weaken_policy_decision(tmp_path: Path, adapter: str):
    _, capability = _scan_payload(
        tmp_path,
        adapter,
        _payload(adapter, "fetch_url", "Fetch an HTTP URL", NETWORK_SCHEMA),
    )
    findings = evaluate_policy(
        [capability],
        Policy(deny={"network.external"}, max_risk_score=100),
        risk_score=capability.risk,
    )

    assert [(finding.severity, finding.rule_id) for finding in findings] == [
        ("HIGH", "capability.denied")
    ]


def test_ambiguous_args_schema_keeps_privilege_without_guessing_framework(tmp_path: Path):
    payload = {
        "tools": [
            {
                "name": "read_file",
                "description": "Read a file",
                "args_schema": PATH_SCHEMA,
            }
        ]
    }
    tool, capability = _scan_payload(tmp_path, "ambiguous", payload)

    assert tool.adapter == "generic"
    assert capability.id == "filesystem.read"
    assert capability.scope.kind == "restricted"
    assert capability.confidence == "low"
    assert capability.evidence[0].adapter == "generic"
