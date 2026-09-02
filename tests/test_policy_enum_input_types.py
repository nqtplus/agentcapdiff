from pathlib import Path

import pytest
import yaml

from agentcapdiff.cli import main
from agentcapdiff.policy import load_policy


@pytest.mark.parametrize(
    "value",
    [[], {}, ["review"], {"value": "review"}, True, 1, None],
)
def test_unknown_scope_rejects_non_string_values(tmp_path: Path, value: object) -> None:
    policy = tmp_path / "agentcapdiff.yml"
    policy.write_text(yaml.safe_dump({"unknown_scope": value}), encoding="utf-8")

    with pytest.raises(ValueError, match="Policy unknown_scope"):
        load_policy(policy)


@pytest.mark.parametrize(
    "value",
    [[], {}, ["trusted"], {"value": "trusted"}, True, 1, None],
)
def test_trust_level_rejects_non_string_values(tmp_path: Path, value: object) -> None:
    policy = tmp_path / "agentcapdiff.yml"
    policy.write_text(
        yaml.safe_dump(
            {
                "trust_boundaries": {
                    "api": {
                        "boundary": "internet",
                        "trust": value,
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Trust boundary for api has invalid trust"):
        load_policy(policy)


def test_cli_scan_normalizes_hostile_unknown_scope_type(tmp_path: Path, capsys) -> None:
    source = tmp_path / "input"
    source.mkdir()
    policy = tmp_path / "agentcapdiff.yml"
    policy.write_text(
        yaml.safe_dump({"unknown_scope": {"value": "review"}}),
        encoding="utf-8",
    )

    assert main(["scan", str(source), "--policy", str(policy), "--fail-on", "never"]) == 3
    stderr = capsys.readouterr().err
    assert "unsafe or invalid scan input/policy" in stderr
    assert "Policy unknown_scope" in stderr


def test_cli_scan_normalizes_hostile_trust_type(tmp_path: Path, capsys) -> None:
    source = tmp_path / "input"
    source.mkdir()
    policy = tmp_path / "agentcapdiff.yml"
    policy.write_text(
        yaml.safe_dump(
            {
                "trust_boundaries": {
                    "api": {
                        "boundary": "internet",
                        "trust": ["trusted"],
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    assert main(["scan", str(source), "--policy", str(policy), "--fail-on", "never"]) == 3
    stderr = capsys.readouterr().err
    assert "unsafe or invalid scan input/policy" in stderr
    assert "Trust boundary for api has invalid trust" in stderr


@pytest.mark.parametrize("unknown_scope", ["deny", "review", "ignore"])
def test_valid_unknown_scope_values_remain_accepted(
    tmp_path: Path,
    unknown_scope: str,
) -> None:
    policy = tmp_path / "agentcapdiff.yml"
    policy.write_text(yaml.safe_dump({"unknown_scope": unknown_scope}), encoding="utf-8")

    assert load_policy(policy).unknown_scope == unknown_scope


@pytest.mark.parametrize("trust", ["trusted", "untrusted", "unknown"])
def test_valid_trust_values_remain_accepted(tmp_path: Path, trust: str) -> None:
    policy = tmp_path / "agentcapdiff.yml"
    policy.write_text(
        yaml.safe_dump(
            {
                "trust_boundaries": {
                    "api": {
                        "boundary": "internet",
                        "trust": trust,
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    assert load_policy(policy).trust_boundaries["api"].trust == trust


def test_short_form_trust_boundary_keeps_unknown_default(tmp_path: Path) -> None:
    policy = tmp_path / "agentcapdiff.yml"
    policy.write_text(
        yaml.safe_dump({"trust_boundaries": {"api": "internet"}}),
        encoding="utf-8",
    )

    boundary = load_policy(policy).trust_boundaries["api"]
    assert boundary.boundary == "internet"
    assert boundary.trust == "unknown"
