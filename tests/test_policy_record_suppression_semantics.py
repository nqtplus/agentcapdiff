from datetime import UTC, datetime, timedelta

import pytest

from agentcapdiff.policy import Policy, Suppression, policy_to_record


def _suppression(**overrides: object) -> Suppression:
    values: dict[str, object] = {
        "rule_id": "capability.review_required",
        "reason": "temporary reviewed exception",
        "expires": datetime.now(UTC).date() + timedelta(days=30),
        "capability": "shell.execute",
        "tool": "repo-tool",
    }
    values.update(overrides)
    return Suppression(**values)  # type: ignore[arg-type]


def test_policy_record_rejects_expired_direct_suppression() -> None:
    policy = Policy(
        suppressions=(
            _suppression(expires=datetime.now(UTC).date() - timedelta(days=1)),
        )
    )

    with pytest.raises(ValueError, match="expired"):
        policy_to_record(policy)


def test_policy_record_accepts_suppression_through_expiry_date() -> None:
    today = datetime.now(UTC).date()
    policy = Policy(suppressions=(_suppression(expires=today),))

    record = policy_to_record(policy)

    assert record["suppressions"][0]["expires"] == today.isoformat()


@pytest.mark.parametrize(
    "suppression, match",
    [
        (_suppression(reason="   "), "reason"),
        (_suppression(rule_id="   "), "rule_id"),
        (_suppression(expires=datetime.now(UTC)), "expires must be a date"),
        (_suppression(expires="2030-01-01"), "expires must be a date"),
        (_suppression(capability="   "), "capability must be a non-empty string"),
        (_suppression(tool="*"), "wildcard"),
    ],
)
def test_policy_record_rejects_invalid_direct_suppression_semantics(
    suppression: Suppression,
    match: str,
) -> None:
    with pytest.raises(ValueError, match=match):
        policy_to_record(Policy(suppressions=(suppression,)))


def test_policy_record_rejects_duplicate_canonical_suppression_selectors() -> None:
    expiry = datetime.now(UTC).date() + timedelta(days=30)
    policy = Policy(
        suppressions=(
            Suppression(
                rule_id="capability.review_required",
                capability="shell.execute",
                tool="repo-tool",
                reason="first",
                expires=expiry,
            ),
            Suppression(
                rule_id="CAPABILITY.REVIEW_REQUIRED",
                capability="SHELL.EXECUTE",
                tool="Repo Tool",
                reason="second",
                expires=expiry,
            ),
        )
    )

    with pytest.raises(ValueError, match="duplicate canonical suppression selectors"):
        policy_to_record(policy)


def test_policy_record_validation_does_not_rewrite_valid_direct_spelling() -> None:
    expiry = datetime.now(UTC).date() + timedelta(days=30)
    policy = Policy(
        suppressions=(
            Suppression(
                rule_id="CAPABILITY.REVIEW_REQUIRED",
                capability="SHELL.EXECUTE",
                tool="Repo-Tool",
                reason="  reviewed migration  ",
                expires=expiry,
            ),
        )
    )

    record = policy_to_record(policy)
    suppression = record["suppressions"][0]

    assert suppression["rule_id"] == "CAPABILITY.REVIEW_REQUIRED"
    assert suppression["capability"] == "SHELL.EXECUTE"
    assert suppression["tool"] == "Repo-Tool"
    assert suppression["reason"] == "  reviewed migration  "
    assert suppression["expires"] == expiry.isoformat()


def test_suppression_expiry_requires_date_not_datetime_subclass() -> None:
    suppression = Suppression(
        rule_id="risk.threshold",
        reason="temporary",
        expires=datetime.now(UTC),  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="expires must be a date"):
        policy_to_record(Policy(suppressions=(suppression,)))
