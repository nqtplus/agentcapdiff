from datetime import date

import pytest

from agentcapdiff.graph import build_capability_graph, capability_graph_to_record
from agentcapdiff.models import ScanResult, ToolRecord
from agentcapdiff.policy import Policy, policy_to_record
from agentcapdiff.result_semantics import ScanResultConsistencyError


def _result_with_schema(schema: dict[object, object]) -> tuple[ScanResult, Policy]:
    policy = Policy(max_risk_score=100)
    result = ScanResult(
        tools=[
            ToolRecord(
                name="catalog_lookup",
                description="Lookup a local catalog",
                source="tools.yaml",
                input_schema=schema,  # type: ignore[arg-type]
            )
        ],
        capabilities=[],
        capability_graph=capability_graph_to_record(build_capability_graph([])),
        policy=policy_to_record(policy),
        findings=[],
    )
    return result, policy


@pytest.mark.parametrize(
    "value",
    [date(2026, 9, 2), b"binary", {"set-member"}],
    ids=["yaml-date", "yaml-binary", "yaml-set"],
)
def test_seal_rejects_yaml_native_values_outside_json(value: object) -> None:
    result, policy = _result_with_schema({"default": value})

    with pytest.raises(ScanResultConsistencyError, match="strict JSON-compatible"):
        result.seal(policy)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_seal_rejects_non_finite_schema_numbers(value: float) -> None:
    result, policy = _result_with_schema({"default": value})

    with pytest.raises(ScanResultConsistencyError, match="non-finite"):
        result.seal(policy)


def test_seal_rejects_non_string_schema_keys() -> None:
    result, policy = _result_with_schema({1: {"type": "string"}})

    with pytest.raises(ScanResultConsistencyError, match="non-string mapping key"):
        result.seal(policy)


def test_seal_accepts_json_compatible_date_like_string() -> None:
    result, policy = _result_with_schema({"default": "2026-09-02"})

    result.seal(policy)
    result.assert_consistent()


def test_sealed_result_rejects_post_seal_non_json_schema_drift() -> None:
    result, policy = _result_with_schema({"default": "2026-09-02"})
    result.seal(policy)
    schema = result.tools[0].input_schema
    assert isinstance(schema, dict)
    schema["default"] = date(2026, 9, 2)

    with pytest.raises(ScanResultConsistencyError, match="strict JSON-compatible"):
        result.to_dict()
