from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_filesystem_scope, infer_network_scope


def test_dynamic_path_template_is_unknown():
    tool = ToolRecord(
        "read_file",
        input_schema={"type": "object", "properties": {"path": {"const": "${WORKSPACE}/reports/**"}}},
    )
    assert infer_filesystem_scope(tool).kind == "unknown"


def test_dynamic_url_template_is_unknown():
    tool = ToolRecord(
        "fetch_url",
        input_schema={"type": "object", "properties": {"url": {"const": "https://${HOST}/v1"}}},
    )
    assert infer_network_scope(tool).kind == "unknown"
