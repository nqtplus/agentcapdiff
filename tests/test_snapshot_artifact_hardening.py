import json
from pathlib import Path

import pytest

from agentcapdiff.cli import main
from agentcapdiff.diffing import capability_fingerprint, compare_snapshots
from agentcapdiff.snapshotio import SnapshotArtifactError, SnapshotLimits


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


def test_snapshot_file_size_is_bounded_before_parsing(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text('{"padding":"' + ("x" * 200) + '"}', encoding="utf-8")
    _write_snapshot(head)

    with pytest.raises(SnapshotArtifactError, match="snapshot artifact exceeds"):
        compare_snapshots(base, head, limits=SnapshotLimits(max_file_bytes=64))


def test_snapshot_structure_depth_is_bounded(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    nested: object = {"leaf": True}
    for _ in range(10):
        nested = {"nested": nested}
    _write_snapshot(base, additive=nested)
    _write_snapshot(head)

    with pytest.raises(SnapshotArtifactError, match="snapshot nesting exceeds depth limit"):
        compare_snapshots(base, head, limits=SnapshotLimits(max_depth=4))


def test_snapshot_structure_node_count_is_bounded(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    _write_snapshot(base, additive=list(range(100)))
    _write_snapshot(head)

    with pytest.raises(SnapshotArtifactError, match="snapshot structure exceeds node limit"):
        compare_snapshots(base, head, limits=SnapshotLimits(max_nodes=20))


def test_snapshot_parser_recursion_is_normalized(tmp_path: Path, monkeypatch) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    _write_snapshot(base)
    _write_snapshot(head)

    def raise_recursion(_text: str, **_kwargs):
        raise RecursionError("simulated parser recursion")

    monkeypatch.setattr("agentcapdiff.snapshotio.json.loads", raise_recursion)
    with pytest.raises(SnapshotArtifactError, match="parser safety limits"):
        compare_snapshots(base, head)


def test_snapshot_rejects_malformed_stable_fields(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    _write_snapshot(base, capabilities={"filesystem.read": True})
    _write_snapshot(head)

    with pytest.raises(SnapshotArtifactError, match="capabilities must be a list of strings"):
        compare_snapshots(base, head)


def test_snapshot_rejects_inconsistent_capability_fingerprint(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    _write_snapshot(
        base,
        capabilities=["filesystem.read"],
        capability_fingerprint="0" * 64,
    )
    _write_snapshot(head)

    with pytest.raises(SnapshotArtifactError, match="does not match capabilities"):
        compare_snapshots(base, head)


def test_snapshot_rejects_unknown_schema_version(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    _write_snapshot(base, schema=2)
    _write_snapshot(head)

    with pytest.raises(SnapshotArtifactError, match="unsupported snapshot schema"):
        compare_snapshots(base, head)


def test_symlinked_snapshot_artifact_is_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.json"
    link = tmp_path / "base.json"
    head = tmp_path / "head.json"
    _write_snapshot(target)
    _write_snapshot(head)
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")

    with pytest.raises(SnapshotArtifactError, match="refusing symlinked snapshot"):
        compare_snapshots(link, head)


def test_cli_diff_fails_closed_for_invalid_snapshot(tmp_path: Path, capsys) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text("[]", encoding="utf-8")
    _write_snapshot(head)

    assert main(["diff", str(base), str(head)]) == 3
    stderr = capsys.readouterr().err
    assert "unsafe or invalid snapshot input" in stderr
    assert "snapshot root must be a JSON object" in stderr


def test_old_snapshot_and_additive_fields_remain_backward_readable(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    old = {
        "risk_score": 0,
        "capabilities": ["filesystem.read"],
        "tools": ["read_file"],
    }
    base.write_text(json.dumps(old), encoding="utf-8")
    head.write_text(
        json.dumps({**old, "future_additive_field": {"safe_to_ignore": True}}),
        encoding="utf-8",
    )

    diff = compare_snapshots(base, head)
    expected = capability_fingerprint(["filesystem.read"])
    assert diff["capabilities_added"] == []
    assert diff["capabilities_removed"] == []
    assert diff["base_capability_fingerprint"] == expected
    assert diff["head_capability_fingerprint"] == expected
    assert diff["fingerprint_changed"] is False
