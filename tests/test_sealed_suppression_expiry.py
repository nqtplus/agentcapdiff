from datetime import UTC, date, datetime, timedelta

import pytest

from agentcapdiff.diffing import snapshot_payload
from agentcapdiff.graph import build_capability_graph, capability_graph_to_record
from agentcapdiff.models import ScanResult
from agentcapdiff.policy import Policy, Suppression, evaluate_policy, policy_to_record
from agentcapdiff.result_semantics import ScanResultConsistencyError


def _sealed_result(expiry: date) -> ScanResult:
    policy = Policy(
        suppressions=(
            Suppression(
                rule_id="risk.threshold",
                reason="temporary reviewed exception",
                expires=expiry,
            ),
        )
    )
    result = ScanResult(
        capability_graph=capability_graph_to_record(build_capability_graph([])),
        policy=policy_to_record(policy),
    )
    result.findings = evaluate_policy([], policy, result.risk_score)
    result.seal(policy)
    return result


def test_sealed_result_is_valid_through_suppression_expiry_date(monkeypatch) -> None:
    expiry = datetime.now(UTC).date() + timedelta(days=1)
    result = _sealed_result(expiry)

    monkeypatch.setattr("agentcapdiff.result_semantics._utc_today", lambda: expiry)

    result.assert_consistent()
    assert result.to_dict()["policy"]["suppressions"][0]["expires"] == expiry.isoformat()
    assert snapshot_payload(result)["policy"]["suppressions"][0]["expires"] == expiry.isoformat()


def test_sealed_result_fails_closed_after_suppression_expires(monkeypatch) -> None:
    expiry = datetime.now(UTC).date() + timedelta(days=1)
    result = _sealed_result(expiry)
    day_after = expiry + timedelta(days=1)

    monkeypatch.setattr("agentcapdiff.result_semantics._utc_today", lambda: day_after)

    with pytest.raises(ScanResultConsistencyError, match="expired policy suppression"):
        result.assert_consistent()
    with pytest.raises(ScanResultConsistencyError, match="expired policy suppression"):
        result.to_dict()
    with pytest.raises(ScanResultConsistencyError, match="expired policy suppression"):
        snapshot_payload(result)


def test_temporal_expiry_does_not_mutate_semantic_fingerprint(monkeypatch) -> None:
    expiry = datetime.now(UTC).date() + timedelta(days=1)
    result = _sealed_result(expiry)
    fingerprint = result._semantic_fingerprint

    monkeypatch.setattr(
        "agentcapdiff.result_semantics._utc_today",
        lambda: expiry + timedelta(days=1),
    )

    with pytest.raises(ScanResultConsistencyError, match="expired policy suppression"):
        result.assert_consistent()
    assert result._semantic_fingerprint == fingerprint
