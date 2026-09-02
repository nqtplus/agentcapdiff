from datetime import UTC, date, datetime, timedelta

import pytest

from agentcapdiff.models import Capability
from agentcapdiff.policy import Policy, Suppression, evaluate_policy


def _capability() -> Capability:
    return Capability(
        id="shell.execute",
        tool="runner",
        risk=40,
        reason="Shell execution detected.",
    )


def _suppression(expires: date, reason: str = "temporary reviewed exception") -> Suppression:
    return Suppression(
        rule_id="capability.denied",
        capability="shell.execute",
        tool="runner",
        reason=reason,
        expires=expires,
    )


def test_expired_direct_suppression_fails_closed() -> None:
    today = datetime.now(UTC).date()
    policy = Policy(
        deny={"shell.execute"},
        suppressions=(_suppression(today - timedelta(days=1)),),
    )

    with pytest.raises(ValueError, match="expired on"):
        evaluate_policy([_capability()], policy, 40)


def test_suppression_is_valid_through_expiry_date() -> None:
    today = datetime.now(UTC).date()
    policy = Policy(
        deny={"shell.execute"},
        suppressions=(_suppression(today),),
    )

    findings = evaluate_policy([_capability()], policy, 40)
    assert len(findings) == 1
    assert findings[0].severity == "INFO"
    assert findings[0].rule_id == "policy.suppressed"


def test_future_direct_suppression_still_applies() -> None:
    today = datetime.now(UTC).date()
    policy = Policy(
        deny={"shell.execute"},
        suppressions=(_suppression(today + timedelta(days=1)),),
    )

    findings = evaluate_policy([_capability()], policy, 40)
    assert [finding.rule_id for finding in findings] == ["policy.suppressed"]


def test_direct_suppression_requires_non_empty_reason() -> None:
    today = datetime.now(UTC).date()
    policy = Policy(
        deny={"shell.execute"},
        suppressions=(_suppression(today + timedelta(days=1), "   "),),
    )

    with pytest.raises(ValueError, match="reason is required"):
        evaluate_policy([_capability()], policy, 40)


def test_direct_suppression_rejects_datetime_expiry() -> None:
    expiry = datetime.now(UTC) + timedelta(days=1)
    policy = Policy(
        deny={"shell.execute"},
        suppressions=(
            Suppression(
                rule_id="capability.denied",
                capability="shell.execute",
                tool="runner",
                reason="temporary reviewed exception",
                expires=expiry,  # type: ignore[arg-type]
            ),
        ),
    )

    with pytest.raises(ValueError, match="expires must be a date"):
        evaluate_policy([_capability()], policy, 40)


def test_direct_suppression_reason_is_normalized() -> None:
    today = datetime.now(UTC).date()
    policy = Policy(
        deny={"shell.execute"},
        suppressions=(
            _suppression(today + timedelta(days=1), "  reviewed exception  "),
        ),
    )

    findings = evaluate_policy([_capability()], policy, 40)
    assert findings[0].message.endswith(": reviewed exception")
