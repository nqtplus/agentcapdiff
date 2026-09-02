import pytest

from agentcapdiff.policy import Policy, ScopeConstraint, policy_to_record


def test_policy_record_rejects_string_deny_instead_of_serializing_characters() -> None:
    policy = Policy(deny="shell.execute")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="effective policy deny"):
        policy_to_record(policy)


@pytest.mark.parametrize(
    "policy, match",
    [
        (Policy(require_review="github.write"), "require_review"),  # type: ignore[arg-type]
        (Policy(max_risk_score=True), "max_risk_score"),  # type: ignore[arg-type]
        (Policy(allow_by_tool=[]), "allow_by_tool must be a mapping"),  # type: ignore[arg-type]
        (
            Policy(scope_constraints={"network.external": {}}),  # type: ignore[dict-item]
            "must be a ScopeConstraint",
        ),
        (Policy(unknown_scope=[]), "unknown_scope"),  # type: ignore[arg-type]
        (Policy(trust_boundaries=[]), "trust_boundaries must be a mapping"),  # type: ignore[arg-type]
        (Policy(suppressions={}), "suppressions must be a sequence"),  # type: ignore[arg-type]
        (Policy(sources="policy.yml"), "sources must be a sequence"),  # type: ignore[arg-type]
    ],
)
def test_policy_record_rejects_malformed_direct_policy_shapes(
    policy: Policy,
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        policy_to_record(policy)


def test_policy_record_preserves_valid_machine_readable_contract() -> None:
    policy = Policy(
        deny=["shell.execute"],  # type: ignore[arg-type]
        require_review=("github.write",),  # type: ignore[arg-type]
        allow_by_tool={"repo": frozenset({"filesystem.read"})},  # type: ignore[dict-item]
        scope_constraints={
            "network.external": ScopeConstraint(
                allowed_kinds=["restricted"],  # type: ignore[arg-type]
                allowed_values=["api.example.com"],  # type: ignore[arg-type]
            )
        },
        suppressions=[],  # type: ignore[arg-type]
        sources=["manual"],  # type: ignore[arg-type]
    )

    record = policy_to_record(policy)

    assert record["schema"] == 1
    assert record["deny"] == ["shell.execute"]
    assert record["require_review"] == ["github.write"]
    assert record["max_risk_score"] == 60
    assert record["allow_by_tool"] == {"repo": ["filesystem.read"]}
    assert record["scope_constraints"] == {
        "network.external": {
            "allowed_kinds": ["restricted"],
            "allowed_values": ["api.example.com"],
        }
    }
    assert record["suppressions"] == []
    assert record["sources"] == ["manual"]
