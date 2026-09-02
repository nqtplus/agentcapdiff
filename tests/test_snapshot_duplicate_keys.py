import json
from pathlib import Path

import pytest

from agentcapdiff.cli import main
from agentcapdiff.diffing import compare_snapshots
from agentcapdiff.snapshotio import SnapshotArtifactError, load_snapshot


def _valid_snapshot() -> dict[str, object]:
    return {
        "schema": 1,
        "risk_score": 0,
        "max_severity": "INFO",
        "capabilities": [],
        "tools": [],
        "findings": [],
    }


def test_snapshot_rejects_duplicate_root_key(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(
        '{"schema":1,"capabilities":["shell.execute"],"capabilities":[],"tools":[]}',
        encoding="utf-8",
    )
    head.write_text(json.dumps(_valid_snapshot()), encoding="utf-8")

    with pytest.raises(SnapshotArtifactError, match="snapshot JSON is malformed"):
        compare_snapshots(base, head)


def test_snapshot_rejects_duplicate_nested_policy_key(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(
        '{"schema":1,"risk_score":0,"max_severity":"INFO",'
        '"capabilities":[],"tools":[],"findings":[],'
        '"policy":{"schema":1,"deny":["shell.execute"],"deny":[]}}',
        encoding="utf-8",
    )

    with pytest.raises(SnapshotArtifactError, match="snapshot JSON is malformed"):
        load_snapshot(snapshot)


def test_snapshot_rejects_duplicate_key_after_json_escape_decoding(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text(
        '{"schema":1,"risk_score":0,"max_severity":"INFO",'
        '"capabilities":[],"tools":[],"findings":[],'
        '"policy":{"deny":[],"\\u0064eny":["shell.execute"]}}',
        encoding="utf-8",
    )

    with pytest.raises(SnapshotArtifactError, match="snapshot JSON is malformed"):
        load_snapshot(snapshot)


def test_same_key_in_distinct_json_objects_remains_valid(tmp_path: Path) -> None:
    snapshot = tmp_path / "snapshot.json"
    payload = _valid_snapshot()
    payload["future_additive_field"] = [{"name": "a"}, {"name": "b"}]
    snapshot.write_text(json.dumps(payload), encoding="utf-8")

    loaded = load_snapshot(snapshot)

    assert loaded["future_additive_field"] == [{"name": "a"}, {"name": "b"}]


def test_cli_diff_duplicate_snapshot_key_fails_closed(tmp_path: Path, capsys) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(
        '{"schema":1,"capabilities":[],"tools":[],"risk_score":0,'
        '"risk_score":100,"max_severity":"INFO","findings":[]}',
        encoding="utf-8",
    )
    head.write_text(json.dumps(_valid_snapshot()), encoding="utf-8")

    assert main(["diff", str(base), str(head)]) == 3
    stderr = capsys.readouterr().err
    assert "unsafe or invalid snapshot input" in stderr
    assert "snapshot JSON is malformed" in stderr
