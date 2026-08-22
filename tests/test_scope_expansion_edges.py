from agentcapdiff.models import ToolRecord
from agentcapdiff.scopes import infer_network_scope, scope_is_expansion


def test_exact_domain_to_wildcard_domain_is_expansion():
    assert scope_is_expansion(
        {"kind": "restricted", "values": ["api.example.com"]},
        {"kind": "restricted", "values": ["*.example.com"]},
    )


def test_invalid_url_port_is_unknown_not_exception():
    tool = ToolRecord(
        "fetch_url",
        input_schema={
            "type": "object",
            "properties": {"url": {"enum": ["https://example.com:not-a-port/"]}},
        },
    )
    assert infer_network_scope(tool).kind == "unknown"
