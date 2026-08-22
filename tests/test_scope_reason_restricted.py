from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_filesystem_scope


def test_restricted_scope_reason_is_explicit():
    scope = infer_filesystem_scope(ToolRecord("read_file", input_schema={"properties": {"path": {"const": "./reports/**"}}}))
    assert scope.kind == "restricted"
    assert "finite" in scope.reason.lower()
