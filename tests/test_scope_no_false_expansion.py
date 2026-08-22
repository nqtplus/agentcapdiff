from agentcapdiff.scopes import scope_is_expansion


def test_scope_narrowing_is_not_expansion():
    assert not scope_is_expansion(
        {"kind": "broad", "values": ["*"]},
        {"kind": "restricted", "values": ["api.example.com"]},
    )
