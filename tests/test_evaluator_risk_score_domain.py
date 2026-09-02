import pytest

from agentcapdiff.policy import Policy, evaluate_policy


@pytest.mark.parametrize(
    "risk_score",
    [False, True, -1, 101, 1.5, "61", None],
)
def test_direct_evaluator_rejects_risk_score_outside_stable_domain(
    risk_score: object,
) -> None:
    with pytest.raises(ValueError, match="risk_score must be an integer from 0 to 100"):
        evaluate_policy([], Policy(), risk_score)  # type: ignore[arg-type]


@pytest.mark.parametrize("risk_score", [0, 60, 100])
def test_direct_evaluator_accepts_integer_risk_score_domain(risk_score: int) -> None:
    policy = Policy(max_risk_score=100)

    assert evaluate_policy([], policy, risk_score) == []


def test_valid_risk_score_still_enforces_threshold() -> None:
    policy = Policy(max_risk_score=60)

    findings = evaluate_policy([], policy, 61)

    assert [finding.rule_id for finding in findings] == ["risk.threshold"]
    assert findings[0].severity == "HIGH"


def test_threshold_boundary_remains_strictly_greater_than() -> None:
    policy = Policy(max_risk_score=60)

    assert evaluate_policy([], policy, 60) == []
