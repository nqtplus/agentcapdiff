from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_network_scope


def test_scope_values_are_deduplicated():
    scope = infer_network_scope(ToolRecord("fetch_url", input_schema={"properties": {"domain": {"enum": ["api.example.com", "api.example.com"]}}}))
    assert scope.values == ("api.example.com",)
