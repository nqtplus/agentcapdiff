from pathlib import Path

import pytest

from agentcapdiff.cli import main
from agentcapdiff.policy import load_policy


@pytest.mark.parametrize(
    ("yaml_value", "case"),
    [
        ("null", "null"),
        ("[60]", "list"),
        ("{value: 60}", "mapping"),
        ("60.5", "float"),
        ('"60"', "string"),
        ("true", "bool"),
        ("-1", "negative"),
        ("101", "above-100"),
    ],
)
def test_policy_file_rejects_invalid_max_risk_score_type_or_range(
    tmp_path: Path,
    yaml_value: str,
    case: str,
) -> None:
    policy = tmp_path / f"policy-{case}.yaml"
    policy.write_text(f"max_risk_score: {yaml_value}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="integer from 0 to 100"):
        load_policy(policy)


@pytest.mark.parametrize("threshold", [0, 100])
def test_policy_file_accepts_max_risk_score_bounds(tmp_path: Path, threshold: int) -> None:
    policy = tmp_path / f"policy-{threshold}.yaml"
    policy.write_text(f"max_risk_score: {threshold}\n", encoding="utf-8")

    loaded = load_policy(policy)

    assert loaded.max_risk_score == threshold
    assert type(loaded.max_risk_score) is int


def test_cli_null_policy_threshold_fails_closed_without_typeerror(
    tmp_path: Path,
    capsys,
) -> None:
    source = tmp_path / "input"
    source.mkdir()
    policy = tmp_path / "policy.yaml"
    policy.write_text("max_risk_score: null\n", encoding="utf-8")

    assert main(["scan", str(source), "--policy", str(policy), "--fail-on", "never"]) == 3
    stderr = capsys.readouterr().err
    assert "unsafe or invalid scan input/policy" in stderr
    assert "integer from 0 to 100" in stderr
    assert "TypeError" not in stderr


def test_cli_snapshot_invalid_threshold_does_not_write_output(
    tmp_path: Path,
    capsys,
) -> None:
    source = tmp_path / "input"
    source.mkdir()
    policy = tmp_path / "policy.yaml"
    policy.write_text("max_risk_score: [60]\n", encoding="utf-8")
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
    stderr = capsys.readouterr().err
    assert "unsafe or invalid scan input/policy" in stderr
    assert "integer from 0 to 100" in stderr
    assert not output.exists()
