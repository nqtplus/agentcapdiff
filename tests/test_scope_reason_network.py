from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_network_scope


def test_unknown_network_scope_has_explainable_reason():
    scope = infer_network_scope(ToolRecord("fetch_url", input_schema={"properties": {"url": {"type": "string"}}}))
    assert scope.kind == "unknown"
    assert "not establish" in scope.reason.lower()
