from agentcapdiff.graph import (
    CAPABILITY_GRAPH_SCHEMA_VERSION,
    build_capability_graph,
    capability_graph_to_record,
)
from agentcapdiff.models import Capability, ScopeEvidence

RISK = {
    "filesystem.read": 10,
    "network.external": 15,
    "secrets.access": 35,
    "email.send": 25,
    "github.write": 20,
    "shell.execute": 35,
}


def _cap(
    capability_id: str,
    tool: str,
    *,
    scope: str = "unknown",
    values: tuple[str, ...] = (),
    confidence: str = "medium",
    source: str = "",
) -> Capability:
    return Capability(
        id=capability_id,
        tool=tool,
        risk=RISK[capability_id],
        reason="test evidence",
        source=source,
        scope=ScopeEvidence(kind=scope, values=values),
        confidence=confidence,
    )


def test_graph_is_versioned_and_deterministic():
    capabilities = [
        _cap("network.external", "fetch_url", scope="restricted", values=("api.example.com",)),
        _cap("secrets.access", "read_secret"),
    ]
    forward = capability_graph_to_record(build_capability_graph(capabilities))
    reversed_record = capability_graph_to_record(build_capability_graph(list(reversed(capabilities))))

    assert forward == reversed_record
    assert forward["schema_version"] == CAPABILITY_GRAPH_SCHEMA_VERSION == "1"
    assert [node["capability"] for node in forward["nodes"]] == [
        "network.external",
        "secrets.access",
    ]


def test_restricted_network_path_keeps_severity_and_confidence_separate():
    graph = build_capability_graph(
        [
            _cap("secrets.access", "read_secret"),
            _cap(
                "network.external",
                "fetch_url",
                scope="restricted",
                values=("api.example.com",),
            ),
        ]
    )
    path = graph.paths[0]

    assert path.id == "possible.secrets_network_exfiltration"
    assert path.severity == "MEDIUM"
    assert path.confidence == "medium"
    assert "possible path only" in path.message.lower()
    assert "not established" in path.message.lower()


def test_unknown_egress_scope_never_reduces_risk_or_claims_safety():
    graph = build_capability_graph(
        [
            _cap("secrets.access", "read_secret", confidence="high"),
            _cap("network.external", "fetch_url", scope="unknown", confidence="high"),
        ]
    )
    path = graph.paths[0]

    assert path.severity == "HIGH"
    assert path.confidence == "low"
    assert any("scope=unknown" in item for item in path.evidence)


def test_supply_chain_combination_is_reported_conservatively():
    graph = build_capability_graph(
        [
            _cap("github.write", "github_push"),
            _cap("shell.execute", "shell_execute"),
        ]
    )

    assert [path.id for path in graph.paths] == [
        "possible.github_shell_supply_chain_mutation"
    ]
    assert graph.paths[0].severity == "HIGH"
    assert "runtime reachability" in graph.paths[0].message.lower()


def test_unpaired_capability_does_not_create_a_path():
    graph = build_capability_graph([_cap("secrets.access", "read_secret")])
    assert graph.paths == ()
    assert graph.edges == ()


def test_path_evidence_is_deduplicated_and_order_independent_for_tied_records():
    records = [
        _cap("secrets.access", "read_secret", confidence="high"),
        _cap(
            "network.external",
            "fetch_url",
            scope="restricted",
            values=("b.example.com", "a.example.com", "a.example.com"),
            confidence="high",
            source="tools.json",
        ),
        _cap(
            "network.external",
            "fetch_url",
            scope="unknown",
            confidence="medium",
            source="tools.json",
        ),
        _cap(
            "network.external",
            "fetch_url",
            scope="restricted",
            values=("b.example.com", "a.example.com", "a.example.com"),
            confidence="high",
            source="tools.json",
        ),
    ]
    forward = build_capability_graph(records).paths[0]
    backward = build_capability_graph(list(reversed(records))).paths[0]

    assert forward == backward
    assert len(forward.evidence) == 3
    assert forward.evidence == tuple(sorted(forward.evidence))
    assert any("a.example.com, b.example.com" in item for item in forward.evidence)
    assert forward.severity == "HIGH"
    assert forward.confidence == "low"


def test_unrecognized_scope_kind_is_conservative_uncertainty():
    graph = build_capability_graph(
        [
            _cap("secrets.access", "read_secret", confidence="high"),
            _cap("network.external", "fetch_url", scope="mystery", confidence="high"),
        ]
    )
    path = graph.paths[0]

    assert path.severity == "HIGH"
    assert path.confidence == "low"
    assert any("scope=mystery" in item for item in path.evidence)


def test_aliased_tool_names_do_not_duplicate_a_rule_path():
    graph = build_capability_graph(
        [
            _cap("secrets.access", "read-secret"),
            _cap("secrets.access", "read secret"),
            _cap("network.external", "fetch-url", scope="restricted"),
            _cap("network.external", "fetch url", scope="restricted"),
        ]
    )

    assert [path.id for path in graph.paths] == ["possible.secrets_network_exfiltration"]
    assert graph.paths[0].tools == ("fetch url", "fetch-url", "read secret", "read-secret")
