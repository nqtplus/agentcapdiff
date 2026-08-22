from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_filesystem_scope


def test_unknown_scope_has_explainable_reason():
    scope = infer_filesystem_scope(ToolRecord("read_file", input_schema={"properties": {"path": {"type": "string"}}}))
    assert scope.kind == "unknown"
    assert "not establish" in scope.reason.lower()
