from typing import Any

import pytest

from agentcapdiff.graph import build_capability_graph, capability_graph_to_record
from agentcapdiff.models import ScanResult
from agentcapdiff.policy import Policy, ScopeConstraint, evaluate_policy, policy_to_record
from agentcapdiff.result_semantics import ScanResultConsistencyError


def _blank_result(*, policy_record: dict[str, Any] | None = None) -> ScanResult:
    return ScanResult(
        capability_graph=capability_graph_to_record(build_capability_graph([])),
        policy=policy_record if policy_record is not None else {},
    )


def _valid_result(policy: Policy) -> ScanResult:
    result = _blank_result(policy_record=policy_to_record(policy))
    result.findings = evaluate_policy([], policy, result.risk_score)
    return result


def test_seal_rejects_string_deny_instead_of_silently_iterating_characters() -> None:
    policy = Policy(deny="shell.execute")  # type: ignore[arg-type]
    result = _blank_result()

    with pytest.raises(
        ScanResultConsistencyError,
        match="effective policy deny must be a collection of strings",
    ):
        result.seal(policy)

    assert result._semantic_fingerprint is None


@pytest.mark.parametrize(
    ("policy", "match"),
    [
        (
            Policy(require_review={"github.write": True}),  # type: ignore[arg-type]
            "require_review must be a collection of strings",
        ),
        (
            Policy(allow_by_tool=[]),  # type: ignore[arg-type]
            "allow_by_tool must be a mapping",
        ),
        (
            Policy(allow_by_tool={"repo": "filesystem.read"}),  # type: ignore[dict-item]
            "allow_by_tool.repo must be a collection of strings",
        ),
        (
            Policy(scope_constraints=[]),  # type: ignore[arg-type]
            "scope_constraints must be a mapping",
        ),
        (
            Policy(
                scope_constraints={
                    "network.external": {"allowed_kinds": ["restricted"]}
                }  # type: ignore[dict-item]
            ),
            "must be a ScopeConstraint",
        ),
        (
            Policy(suppressions={"rule_id": "capability.denied"}),  # type: ignore[arg-type]
            "suppressions must be a sequence of Suppression values",
        ),
        (
            Policy(suppressions=[{"rule_id": "capability.denied"}]),  # type: ignore[list-item]
            "suppressions must contain Suppression values",
        ),
        (
            Policy(sources="agentcapdiff.yml"),  # type: ignore[arg-type]
            "sources must be a sequence of strings",
        ),
    ],
)
def test_seal_rejects_malformed_effective_policy_containers(
    policy: Policy,
    match: str,
) -> None:
    result = _blank_result()

    with pytest.raises(ScanResultConsistencyError, match=match):
        result.seal(policy)

    assert result._semantic_fingerprint is None


def test_seal_rejects_invalid_scope_constraint_kind_collection() -> None:
    policy = Policy(
        scope_constraints={
            "network.external": ScopeConstraint(
                allowed_kinds="restricted",  # type: ignore[arg-type]
            )
        }
    )
    result = _blank_result()

    with pytest.raises(
        ScanResultConsistencyError,
        match="allowed_kinds must be a collection of strings",
    ):
        result.seal(policy)


def test_reasonable_direct_library_collection_variants_remain_compatible() -> None:
    policy = Policy(
        deny=["shell.execute"],  # type: ignore[arg-type]
        require_review=("github.write",),  # type: ignore[arg-type]
        allow_by_tool={"repo": ["filesystem.read"]},  # type: ignore[dict-item]
        scope_constraints={
            "network.external": ScopeConstraint(
                allowed_kinds={"restricted"},  # type: ignore[arg-type]
                allowed_values=["api.example.com"],  # type: ignore[arg-type]
            )
        },
        suppressions=[],  # type: ignore[arg-type]
        sources=["manual"],  # type: ignore[arg-type]
    )
    result = _valid_result(policy)

    result.seal(policy)
    result.assert_consistent()

    assert result._semantic_fingerprint is not None
