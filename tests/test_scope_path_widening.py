from agentcapdiff.scopes import scope_is_expansion


def test_nested_path_glob_widening_is_expansion():
    assert scope_is_expansion(
        {"kind": "restricted", "values": ["./reports/private/**"]},
        {"kind": "restricted", "values": ["./reports/**"]},
    )
