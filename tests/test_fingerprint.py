from agentcapdiff.diffing import capability_fingerprint, snapshot_payload
from agentcapdiff.models import Capability, ScanResult, ToolRecord


def test_fingerprint_is_order_independent():
    first = capability_fingerprint(["shell.execute", "filesystem.read"])
    second = capability_fingerprint(["filesystem.read", "shell.execute"])
    assert first == second


def test_fingerprint_deduplicates_capabilities():
    first = capability_fingerprint(["filesystem.read"])
    second = capability_fingerprint(["filesystem.read", "filesystem.read"])
    assert first == second


def test_fingerprint_changes_when_capability_surface_changes():
    before = capability_fingerprint(["filesystem.read"])
    after = capability_fingerprint(["filesystem.read", "shell.execute"])
    assert before != after


def test_snapshot_fingerprint_ignores_source_paths_and_tool_names():
    first = ScanResult(
        tools=[ToolRecord("reader_a", source="/checkout/a/tools.json")],
        capabilities=[
            Capability(
                "filesystem.read",
                "reader_a",
                10,
                "Can read local files.",
                "/checkout/a/tools.json",
            )
        ],
    )
    second = ScanResult(
        tools=[ToolRecord("reader_b", source="/different/path/tools.json")],
        capabilities=[
            Capability(
                "filesystem.read",
                "reader_b",
                10,
                "Can read local files.",
                "/different/path/tools.json",
            )
        ],
    )
    assert (
        snapshot_payload(first)["capability_fingerprint"]
        == snapshot_payload(second)["capability_fingerprint"]
    )
