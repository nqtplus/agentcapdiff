from agentcapdiff.scopes import scope_is_expansion


def test_unknown_transitions_are_not_proven_expansions():
    assert not scope_is_expansion(
        {"kind": "unknown", "values": []},
        {"kind": "broad", "values": ["*"]},
    )
    assert not scope_is_expansion(
        {"kind": "restricted", "values": ["api.example.com"]},
        {"kind": "unknown", "values": []},
    )
