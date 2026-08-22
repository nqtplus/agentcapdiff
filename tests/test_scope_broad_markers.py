from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_filesystem_scope, infer_network_scope


def test_root_path_marker_is_broad():
    tool = ToolRecord("read_file", input_schema={"type": "object", "properties": {"path": {"const": "/"}}})
    assert infer_filesystem_scope(tool).kind == "broad"


def test_any_host_marker_is_broad():
    tool = ToolRecord("fetch_url", input_schema={"type": "object", "properties": {"domain": {"const": "*"}}})
    assert infer_network_scope(tool).kind == "broad"
