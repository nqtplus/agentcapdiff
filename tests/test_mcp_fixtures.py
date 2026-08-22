from pathlib import Path

import pytest
from agentcapdiff.scanner import scan


FIXTURES = Path(__file__).parent / "fixtures" / "mcp"


@pytest.mark.parametrize(
    ("name", "expected_capability", "expected_scope"),
    [
        ("filesystem_restricted.json", "filesystem.read", "restricted"),
        ("filesystem_ambiguous.yaml", "filesystem.write", "unknown"),
        ("network_exact.json", "network.external", "restricted"),
        ("network_wildcard.yaml", "network.external", "restricted"),
        ("network_broad.json", "network.external", "broad"),
        ("network_unknown.yaml", "network.external", "unknown"),
    ],
)
def test_fixture_classification(name: str, expected_capability: str, expected_scope: str):
    result = scan(FIXTURES / name)
    matches = [cap for cap in result.capabilities if cap.id == expected_capability]
    assert matches
    assert matches[0].scope.kind == expected_scope


def test_negative_fixture_does_not_match_high_risk_capability():
    result = scan(FIXTURES / "negative_catalog_search.json")
    assert {cap.id for cap in result.capabilities}.isdisjoint(
        {"shell.execute", "secrets.access", "filesystem.write", "github.write", "email.send"}
    )
