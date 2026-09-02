import pytest

from agentcapdiff.models import Capability
from agentcapdiff.policy import Policy, ScopeConstraint, evaluate_policy


def _cap(capability: str = "shell.execute", tool: str = "shell") -> Capability:
    return Capability(id=capability, tool=tool, risk=10, reason="test")


def test_direct_evaluator_rejects_string_deny_instead_of_iterating_characters() -> None:
    policy = Policy(deny="shell.execute")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="effective policy deny"):
        evaluate_policy([_cap()], policy, 10)


@pytest.mark.parametrize(
    "policy, match",
    [
        (Policy(require_review="github.write"), "require_review"),  # type: ignore[arg-type]
        (Policy(max_risk_score=True), "max_risk_score"),  # type: ignore[arg-type]
        (Policy(allow_by_tool=[]), "allow_by_tool must be a mapping"),  # type: ignore[arg-type]
        (
            Policy(allow_by_tool={"repo": "filesystem.read"}),  # type: ignore[dict-item]
            "allow_by_tool.repo",
        ),
        (
            Policy(scope_constraints=[]),  # type: ignore[arg-type]
            "scope_constraints must be a mapping",
        ),
        (
            Policy(scope_constraints={"network.external": {}}),  # type: ignore[dict-item]
            "must be a ScopeConstraint",
        ),
        (
            Policy(
                scope_constraints={
                    "network.external": ScopeConstraint(
                        allowed_kinds="restricted",  # type: ignore[arg-type]
                    )
                }
            ),
            "allowed_kinds",
        ),
        (Policy(unknown_scope=[]), "unknown_scope"),  # type: ignore[arg-type]
        (
            Policy(trust_boundaries=[]),  # type: ignore[arg-type]
            "trust_boundaries must be a mapping",
        ),
        (
            Policy(suppressions={}),  # type: ignore[arg-type]
            "suppressions must be a sequence",
        ),
        (Policy(sources="policy.yml"), "sources must be a sequence"),  # type: ignore[arg-type]
    ],
)
def test_direct_evaluator_rejects_malformed_policy_containers(
    policy: Policy,
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        evaluate_policy([_cap()], policy, 10)


@pytest.mark.parametrize(
    "deny",
    [
        {"shell.execute"},
        frozenset({"shell.execute"}),
        ["shell.execute"],
        ("shell.execute",),
    ],
)
def test_direct_evaluator_preserves_unambiguous_string_collection_variants(
    deny: object,
) -> None:
    policy = Policy(deny=deny)  # type: ignore[arg-type]
    findings = evaluate_policy([_cap()], policy, 10)

    assert [finding.rule_id for finding in findings] == ["capability.denied"]
    assert findings[0].severity == "HIGH"


def test_direct_evaluator_accepts_unambiguous_nested_collection_variants() -> None:
    policy = Policy(
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

    assert evaluate_policy([], policy, 0) == []
