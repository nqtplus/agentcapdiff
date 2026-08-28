import json
import os
from pathlib import Path

import pytest

from agentcapdiff.benchmark import main as benchmark_main
from agentcapdiff.cli import main
from agentcapdiff.outputio import OutputWriteError, atomic_write_text


def _empty_scan_root(tmp_path: Path) -> Path:
    source = tmp_path / "input"
    source.mkdir()
    return source


def _make_symlink(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable on this platform")


def test_scan_output_rejects_symlink_and_preserves_target(
    tmp_path: Path,
    capsys,
) -> None:
    source = _empty_scan_root(tmp_path)
    victim = tmp_path / "victim.json"
    victim.write_text("do not overwrite", encoding="utf-8")
    output = tmp_path / "report.json"
    _make_symlink(output, victim)

    assert (
        main(
            [
                "scan",
                str(source),
                "--format",
                "json",
                "--output",
                str(output),
                "--fail-on",
                "never",
            ]
        )
        == 3
    )
    assert victim.read_text(encoding="utf-8") == "do not overwrite"
    assert "unsafe or invalid output path" in capsys.readouterr().err


def test_snapshot_output_rejects_symlink_and_preserves_target(
    tmp_path: Path,
    capsys,
) -> None:
    source = _empty_scan_root(tmp_path)
    victim = tmp_path / "victim.json"
    victim.write_text("do not overwrite", encoding="utf-8")
    output = tmp_path / "snapshot.json"
    _make_symlink(output, victim)

    assert main(["snapshot", str(source), "--output", str(output)]) == 3
    assert victim.read_text(encoding="utf-8") == "do not overwrite"
    assert "unsafe or invalid output path" in capsys.readouterr().err


def test_output_rejects_symlinked_parent(tmp_path: Path, capsys) -> None:
    source = _empty_scan_root(tmp_path)
    real_parent = tmp_path / "real-output"
    real_parent.mkdir()
    redirected_parent = tmp_path / "redirected-output"
    _make_symlink(redirected_parent, real_parent, directory=True)
    output = redirected_parent / "report.json"

    assert (
        main(
            [
                "scan",
                str(source),
                "--format",
                "json",
                "--output",
                str(output),
                "--fail-on",
                "never",
            ]
        )
        == 3
    )
    assert not (real_parent / "report.json").exists()
    assert "unsafe or invalid output path" in capsys.readouterr().err


def test_output_rejects_non_regular_destination(tmp_path: Path, capsys) -> None:
    source = _empty_scan_root(tmp_path)
    output = tmp_path / "report.json"
    output.mkdir()

    assert (
        main(
            [
                "scan",
                str(source),
                "--format",
                "json",
                "--output",
                str(output),
                "--fail-on",
                "never",
            ]
        )
        == 3
    )
    assert "output path must be a regular file" in capsys.readouterr().err


def test_atomic_replace_failure_preserves_existing_output_and_cleans_temp(
    tmp_path: Path,
    monkeypatch,
) -> None:
    output = tmp_path / "report.json"
    output.write_text("old complete report\n", encoding="utf-8")

    def fail_replace(*_args, **_kwargs):
        raise OSError("simulated replace failure")

    monkeypatch.setattr("agentcapdiff.outputio.os.replace", fail_replace)
    with pytest.raises(OutputWriteError, match="cannot write output safely"):
        atomic_write_text(output, "new complete report\n")

    assert output.read_text(encoding="utf-8") == "old complete report\n"
    leftovers = [path for path in tmp_path.iterdir() if ".agentcapdiff-" in path.name]
    assert leftovers == []


def test_symlink_swap_at_atomic_replace_never_overwrites_link_target(
    tmp_path: Path,
    monkeypatch,
) -> None:
    output = tmp_path / "report.json"
    output.write_text("old report\n", encoding="utf-8")
    victim = tmp_path / "victim.txt"
    victim.write_text("victim stays unchanged\n", encoding="utf-8")
    real_replace = os.replace

    def racing_replace(src, dst, *args, **kwargs):
        output.unlink()
        _make_symlink(output, victim)
        return real_replace(src, dst, *args, **kwargs)

    monkeypatch.setattr("agentcapdiff.outputio.os.replace", racing_replace)
    atomic_write_text(output, "new report\n")

    assert output.is_file()
    assert not output.is_symlink()
    assert output.read_text(encoding="utf-8") == "new report\n"
    assert victim.read_text(encoding="utf-8") == "victim stays unchanged\n"


def test_benchmark_output_uses_fail_closed_writer(tmp_path: Path, capsys) -> None:
    victim = tmp_path / "victim.json"
    victim.write_text("keep", encoding="utf-8")
    output = tmp_path / "benchmark.json"
    _make_symlink(output, victim)

    assert (
        benchmark_main(
            [
                "--manifest",
                "benchmarks/manifest.json",
                "--baseline",
                "benchmarks/baseline.json",
                "--output",
                str(output),
            ]
        )
        == 1
    )
    assert victim.read_text(encoding="utf-8") == "keep"
    assert "unsafe or invalid output path" in capsys.readouterr().err


def test_successful_atomic_output_remains_valid_json(tmp_path: Path) -> None:
    source = _empty_scan_root(tmp_path)
    output = tmp_path / "report.json"
    output.write_text("old", encoding="utf-8")

    assert (
        main(
            [
                "scan",
                str(source),
                "--format",
                "json",
                "--output",
                str(output),
                "--fail-on",
                "never",
            ]
        )
        == 0
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["risk_score"] == 0
