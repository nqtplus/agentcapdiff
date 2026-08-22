from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_network_scope


def test_broad_scope_reason_is_explicit():
    scope = infer_network_scope(ToolRecord("fetch_url", "Fetch any arbitrary URL"))
    assert scope.kind == "broad"
    assert "arbitrary" in scope.reason.lower()
