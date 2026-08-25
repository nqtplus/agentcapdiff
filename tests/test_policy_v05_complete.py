from datetime import date
from pathlib import Path

import pytest

from agentcapdiff.diffing import compare_snapshots
from agentcapdiff.formats import markdown_diff_report, text_report
from agentcapdiff.models import Capability, ScanResult
from agentcapdiff.policy import evaluate_policy, load_policy, policy_to_record


def _cap(capability: str, tool: str) -> Capability:
    return Capability(id=capability, tool=tool, risk=10, reason="test")


def test_policy_inheritance_has_deterministic_parent_then_child_precedence(tmp_path: Path) -> None:
    (tmp_path / "base-a.yml").write_text(
        "deny:\n  - shell.execute\nmax_risk_score: 40\n"
        "allow_by_tool:\n  repo:\n    - filesystem.read\n",
        encoding="utf-8",
    )
    (tmp_path / "base-b.yml").write_text(
        "max_risk_score: 70\nrequire_review:\n  - github.write\n",
        encoding="utf-8",
    )
    child = tmp_path / "agentcapdiff.yml"
    child.write_text(
        "extends:\n  - base-a.yml\n  - base-b.yml\n"
        "max_risk_score: 55\n"
        "allow_by_tool:\n  repo:\n    - filesystem.write\n",
        encoding="utf-8",
    )

    policy = load_policy(child)
    assert policy.deny == {"shell.execute"}
    assert policy.require_review == {"github.write"}
    assert policy.max_risk_score == 55
    assert policy.allow_by_tool == {"repo": {"filesystem.write"}}
    assert policy.sources == ("base-a.yml", "base-b.yml", "agentcapdiff.yml")


def test_policy_inheritance_cycle_is_rejected(tmp_path: Path) -> None:
    first = tmp_path / "first.yml"
    second = tmp_path / "second.yml"
    first.write_text("extends: second.yml\n", encoding="utf-8")
    second.write_text("extends: first.yml\n", encoding="utf-8")
    with pytest.raises(ValueError, match="cycle"):
        load_policy(first)


def test_policy_inheritance_cannot_escape_root_directory(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    outside = tmp_path / "outside.yml"
    outside.write_text("deny: [shell.execute]\n", encoding="utf-8")
    policy_path = root / "agentcapdiff.yml"
    policy_path.write_text("extends: ../outside.yml\n", encoding="utf-8")
    with pytest.raises(ValueError, match="root policy directory"):
        load_policy(policy_path)


def test_trust_boundary_annotations_are_normalized_and_visible(tmp_path: Path) -> None:
    path = tmp_path / "agentcapdiff.yml"
    path.write_text(
        "trust_boundaries:\n"
        "  api_client:\n"
        "    boundary: internet\n"
        "    trust: untrusted\n"
        "    note: third-party service\n",
        encoding="utf-8",
    )
    policy = load_policy(path)
    record = policy_to_record(policy)
    assert record["trust_boundaries"]["api_client"] == {
        "boundary": "internet",
        "trust": "untrusted",
        "note": "third-party service",
    }

    result = ScanResult(policy=record)
    report = text_report(result)
    assert "Trust-boundary annotations" in report
    assert "api_client: internet / trust=untrusted" in report


def test_suppression_requires_reason_and_expiry(tmp_path: Path) -> None:
    path = tmp_path / "agentcapdiff.yml"
    path.write_text(
        "suppressions:\n"
        "  - rule_id: capability.review_required\n"
        "    expires: 2030-01-01\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="reason"):
        load_policy(path, today=date(2026, 8, 25))


def test_expired_suppression_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "agentcapdiff.yml"
    path.write_text(
        "suppressions:\n"
        "  - rule_id: capability.review_required\n"
        "    reason: temporary migration\n"
        "    expires: 2026-08-24\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="expired"):
        load_policy(path, today=date(2026, 8, 25))


def test_active_suppression_is_temporary_and_visible(tmp_path: Path) -> None:
    path = tmp_path / "agentcapdiff.yml"
    path.write_text(
        "require_review:\n  - shell.execute\n"
        "suppressions:\n"
        "  - rule_id: capability.review_required\n"
        "    capability: shell.execute\n"
        "    tool: shell\n"
        "    reason: reviewed migration window\n"
        "    expires: 2026-08-30\n",
        encoding="utf-8",
    )
    policy = load_policy(path, today=date(2026, 8, 25))
    findings = evaluate_policy([_cap("shell.execute", "shell")], policy, 10)
    assert [finding.rule_id for finding in findings] == ["policy.suppressed"]
    assert findings[0].severity == "INFO"
    assert "2026-08-30" in findings[0].message
    assert "reviewed migration window" in findings[0].message


def _write_snapshot(path: Path, policy: dict) -> None:
    path.write_text(
        __import__("json").dumps(
            {
                "schema": 1,
                "risk_score": 10,
                "max_severity": "INFO",
                "capabilities": [],
                "tools": [],
                "scopes": [],
                "findings": [],
                "policy": policy,
            }
        ),
        encoding="utf-8",
    )


def test_policy_weakening_is_detected_without_capability_change(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base_policy = {
        "schema": 1,
        "deny": ["secrets.access"],
        "require_review": ["shell.execute"],
        "max_risk_score": 60,
        "allow_by_tool": {"repo": ["filesystem.read"]},
        "scope_constraints": {
            "network.external": {
                "allowed_kinds": ["restricted"],
                "allowed_values": ["api.example.com"],
            }
        },
        "unknown_scope": "deny",
        "trust_boundaries": {
            "repo": {"boundary": "repository", "trust": "trusted", "note": ""}
        },
        "suppressions": [],
        "sources": ["agentcapdiff.yml"],
    }
    head_policy = {
        "schema": 1,
        "deny": [],
        "require_review": [],
        "max_risk_score": 80,
        "allow_by_tool": {"repo": ["filesystem.read", "filesystem.write"]},
        "scope_constraints": {
            "network.external": {
                "allowed_kinds": ["restricted", "broad"],
                "allowed_values": ["api.example.com", "*"],
            }
        },
        "unknown_scope": "ignore",
        "trust_boundaries": {},
        "suppressions": [
            {
                "rule_id": "risk.threshold",
                "capability": None,
                "tool": None,
                "reason": "temporary exception",
                "expires": "2026-08-30",
            }
        ],
        "sources": ["agentcapdiff.yml"],
    }
    _write_snapshot(base, base_policy)
    _write_snapshot(head, head_policy)

    diff = compare_snapshots(base, head)
    kinds = {warning["kind"] for warning in diff["policy_weakening_warnings"]}
    assert diff["policy_changed"] is True
    assert {
        "deny_removed",
        "review_requirement_removed",
        "risk_threshold_raised",
        "unknown_scope_weakened",
        "tool_allowlist_expanded",
        "scope_kind_expanded",
        "scope_values_expanded",
        "suppression_added",
        "trust_boundary_removed",
    }.issubset(kinds)
    assert diff["capabilities_added"] == []
    assert diff["capabilities_removed"] == []

    markdown = markdown_diff_report(diff)
    assert "Policy weakening warnings" in markdown
    assert "Global deny removed" in markdown
    assert "Temporary policy suppression added" in markdown


def test_old_snapshot_without_policy_remains_readable(tmp_path: Path) -> None:
    base = tmp_path / "base.json"
    head = tmp_path / "head.json"
    base.write_text(
        '{"schema": 1, "risk_score": 0, "capabilities": [], "tools": [], "findings": []}',
        encoding="utf-8",
    )
    _write_snapshot(
        head,
        {
            "schema": 1,
            "deny": [],
            "require_review": [],
            "max_risk_score": 60,
            "allow_by_tool": {},
            "scope_constraints": {},
            "unknown_scope": "review",
            "trust_boundaries": {},
            "suppressions": [],
            "sources": ["agentcapdiff.yml"],
        },
    )
    diff = compare_snapshots(base, head)
    assert diff["policy_changed"] is False
    assert diff["policy_weakening_warnings"] == []
