from agentcapdiff.scopes import scope_is_expansion


def test_exact_host_to_wildcard_host_is_expansion():
    assert scope_is_expansion(
        {"kind": "restricted", "values": ["api.example.com"]},
        {"kind": "restricted", "values": ["*.example.com"]},
    )
