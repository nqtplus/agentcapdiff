from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_network_scope


def test_scope_values_have_deterministic_order():
    scope = infer_network_scope(ToolRecord("fetch_url", input_schema={"properties": {"domain": {"enum": ["z.example.com", "a.example.com"]}}}))
    assert scope.values == ("a.example.com", "z.example.com")
