import json
from pathlib import Path

import pytest

from agentcapdiff.cli import main
from agentcapdiff.snapshotio import SnapshotArtifactError, load_snapshot


def _write_snapshot(path: Path, **overrides) -> None:
    payload = {
        "schema": 1,
        "risk_score": 0,
        "max_severity": "INFO",
        "capabilities": [],
        "tools": [],
        "findings": [],
    }
    payload.update(overrides)
    path.write_text(json.dumps(payload), encoding="utf-8")


@pytest.mark.parametrize("value", [[], {}, ["INFO"], {"value": "INFO"}])
def test_snapshot_max_severity_rejects_non_string_values(
    tmp_path: Path,
    value: object,
) -> None:
    snapshot = tmp_path / "snapshot.json"
    _write_snapshot(snapshot, max_severity=value)

    with pytest.raises(SnapshotArtifactError, match="max_severity is invalid"):
        load_snapshot(snapshot)


@pytest.mark.parametrize("value", [[], {}, ["review"], {"value": "review"}])
def test_snapshot_unknown_scope_rejects_non_string_values(
    tmp_path: Path,
    value: object,
) -> None:
    snapshot = tmp_path / "snapshot.json"
    _write_snapshot(snapshot, policy={"unknown_scope": value})

    with pytest.raises(SnapshotArtifactError, match="policy.unknown_scope"):
        load_snapshot(snapshot)


def test_cli_diff_normalizes_hostile_snapshot_enum_type(tmp_path: Path, capsys) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    _write_snapshot(base, policy={"unknown_scope": {"value": "review"}})
    _write_snapshot(head)

    assert main(["diff", str(base), str(head)]) == 3
    stderr = capsys.readouterr().err
    assert "unsafe or invalid snapshot input" in stderr
    assert "policy.unknown_scope" in stderr


def test_valid_snapshot_enum_strings_remain_readable(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot.json"
    _write_snapshot(
        snapshot,
        max_severity="INFO",
        policy={"unknown_scope": "review"},
    )

    loaded = load_snapshot(snapshot)
    assert loaded["max_severity"] == "INFO"
    assert loaded["policy"]["unknown_scope"] == "review"
