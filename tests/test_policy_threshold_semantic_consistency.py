from pathlib import Path

import pytest

from agentcapdiff.cli import main
from agentcapdiff.graph import build_capability_graph, capability_graph_to_record
from agentcapdiff.models import ScanResult
from agentcapdiff.policy import Policy, policy_to_record
from agentcapdiff.result_semantics import ScanResultConsistencyError


def _empty_result(policy: Policy) -> ScanResult:
    return ScanResult(
        tools=[],
        capabilities=[],
        findings=[],
        capability_graph=capability_graph_to_record(build_capability_graph([])),
        policy=policy_to_record(policy),
    )


@pytest.mark.parametrize(
    "threshold",
    [True, -1, 101, 60.5, "60"],
    ids=["bool", "negative", "above-100", "float", "string"],
)
def test_seal_rejects_invalid_effective_policy_threshold(threshold: object) -> None:
    policy = Policy(max_risk_score=threshold)  # type: ignore[arg-type]
    result = _empty_result(policy)

    with pytest.raises(ScanResultConsistencyError, match="integer from 0 to 100"):
        result.seal(policy)


@pytest.mark.parametrize("threshold", [0, 100])
def test_seal_accepts_policy_threshold_bounds(threshold: int) -> None:
    policy = Policy(max_risk_score=threshold)
    result = _empty_result(policy)

    result.seal(policy)
    result.assert_consistent()


def test_cli_snapshot_rejects_out_of_range_policy_before_writing(tmp_path: Path, capsys) -> None:
    source = tmp_path / "input"
    source.mkdir()
    policy = tmp_path / "policy.yaml"
    policy.write_text("max_risk_score: 999\n", encoding="utf-8")
    output = tmp_path / "snapshot.json"

    assert (
        main(
            [
                "snapshot",
                str(source),
                "--policy",
                str(policy),
                "--output",
                str(output),
            ]
        )
        == 3
    )
    captured = capsys.readouterr()
    assert "unsafe or invalid scan input/policy" in captured.err
    assert "integer from 0 to 100" in captured.err
    assert not output.exists()
