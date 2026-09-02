from typing import Any

import pytest

from agentcapdiff.graph import build_capability_graph, capability_graph_to_record
from agentcapdiff.models import ScanResult
from agentcapdiff.policy import Policy, TrustBoundary, evaluate_policy, policy_to_record
from agentcapdiff.result_semantics import ScanResultConsistencyError


def _result_for(policy: Policy, *, policy_record: dict[str, Any] | None = None) -> ScanResult:
    result = ScanResult(
        capability_graph=capability_graph_to_record(build_capability_graph([])),
        policy=policy_record if policy_record is not None else policy_to_record(policy),
    )
    try:
        result.findings = evaluate_policy([], policy, result.risk_score)
    except ValueError:
        # Invalid-policy tests below intentionally exercise the independent seal boundary.
        # Audit #34 makes direct evaluation fail closed earlier, so leave the default
        # empty findings in place and let result.seal(policy) assert its own error type.
        result.findings = []
    return result


@pytest.mark.parametrize("value", [[], {}, True, 1, "unsafe"])
def test_seal_rejects_invalid_effective_unknown_scope(value: object) -> None:
    policy = Policy(unknown_scope=value)  # type: ignore[arg-type]
    result = _result_for(policy)

    with pytest.raises(ScanResultConsistencyError, match="effective policy unknown_scope"):
        result.seal(policy)

    assert result._semantic_fingerprint is None


@pytest.mark.parametrize("value", [[], {}, True, 1, "unsafe"])
def test_seal_rejects_invalid_effective_trust_level(value: object) -> None:
    policy = Policy(
        trust_boundaries={
            "api": TrustBoundary(
                boundary="internet",
                trust=value,  # type: ignore[arg-type]
            )
        }
    )
    result = _result_for(policy)

    with pytest.raises(ScanResultConsistencyError, match="has invalid trust"):
        result.seal(policy)

    assert result._semantic_fingerprint is None


def test_seal_rejects_non_mapping_effective_trust_boundaries() -> None:
    policy = Policy(trust_boundaries=[])  # type: ignore[arg-type]
    result = _result_for(policy, policy_record={})

    with pytest.raises(
        ScanResultConsistencyError,
        match="trust_boundaries must be a mapping",
    ):
        result.seal(policy)

    assert result._semantic_fingerprint is None


def test_seal_rejects_non_string_effective_trust_boundary_key() -> None:
    policy = Policy(
        trust_boundaries={
            7: TrustBoundary(boundary="internet"),  # type: ignore[dict-item]
        }
    )
    result = _result_for(policy, policy_record={})

    with pytest.raises(
        ScanResultConsistencyError,
        match="trust_boundaries keys must be strings",
    ):
        result.seal(policy)


def test_seal_rejects_invalid_effective_trust_boundary_shape() -> None:
    policy = Policy(
        trust_boundaries={
            "api": TrustBoundary(
                boundary=7,  # type: ignore[arg-type]
                note=[],  # type: ignore[arg-type]
            )
        }
    )
    result = _result_for(policy)

    with pytest.raises(ScanResultConsistencyError, match="non-empty boundary"):
        result.seal(policy)


def test_valid_effective_policy_still_seals() -> None:
    policy = Policy(
        unknown_scope="review",
        trust_boundaries={
            "api": TrustBoundary(
                boundary="internet",
                trust="untrusted",
                note="third-party service",
            )
        },
    )
    result = _result_for(policy)

    result.seal(policy)
    result.assert_consistent()
    assert result._semantic_fingerprint is not None
