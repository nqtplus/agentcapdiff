from pathlib import Path

import pytest

from agentcapdiff.models import Capability, ScopeEvidence
from agentcapdiff.policy import Policy, ScopeConstraint, evaluate_policy, load_policy


def cap(capability: str, tool: str, scope: ScopeEvidence | None = None) -> Capability:
    return Capability(
        id=capability,
        tool=tool,
        risk=10,
        reason="test",
        scope=scope or ScopeEvidence(),
    )


def test_legacy_policy_remains_backward_compatible(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text("deny:\n  - shell.execute\nrequire_review:\n  - github.write\nmax_risk_score: 70\n")
    policy = load_policy(path)
    assert policy.deny == {"shell.execute"}
    assert policy.require_review == {"github.write"}
    assert policy.max_risk_score == 70
    assert policy.allow_by_tool == {}
    assert policy.scope_constraints == {}
    assert policy.unknown_scope == "review"


def test_tool_allowlist_blocks_unlisted_capability() -> None:
    policy = Policy(allow_by_tool={"repo_tool": {"filesystem.read"}})
    findings = evaluate_policy([cap("filesystem.write", "repo_tool")], policy, 10)
    assert [f.rule_id for f in findings] == ["capability.tool_allowlist_violation"]
    assert findings[0].severity == "HIGH"


def test_scope_constraint_allows_exact_restricted_values() -> None:
    policy = Policy(
        scope_constraints={
            "network.external": ScopeConstraint(
                allowed_kinds=frozenset({"restricted"}),
                allowed_values=("api.example.com",),
            )
        }
    )
    capability = cap(
        "network.external",
        "fetch",
        ScopeEvidence(kind="restricted", values=("api.example.com",), reason="test"),
    )
    assert evaluate_policy([capability], policy, 10) == []


def test_scope_constraint_fails_closed_on_broad_scope() -> None:
    policy = Policy(
        scope_constraints={"filesystem.write": ScopeConstraint()}
    )
    capability = cap(
        "filesystem.write",
        "writer",
        ScopeEvidence(kind="broad", values=("/**",), reason="test"),
    )
    findings = evaluate_policy([capability], policy, 10)
    assert [f.rule_id for f in findings] == ["scope.constraint_violation"]
    assert findings[0].severity == "HIGH"


def test_unknown_scope_defaults_to_review_not_safe() -> None:
    policy = Policy(scope_constraints={"network.external": ScopeConstraint()})
    findings = evaluate_policy([cap("network.external", "fetch")], policy, 10)
    assert [f.rule_id for f in findings] == ["scope.unknown"]
    assert findings[0].severity == "MEDIUM"


def test_unknown_scope_can_be_denied_explicitly() -> None:
    policy = Policy(
        scope_constraints={"network.external": ScopeConstraint()},
        unknown_scope="deny",
    )
    findings = evaluate_policy([cap("network.external", "fetch")], policy, 10)
    assert findings[0].severity == "HIGH"


def test_invalid_unknown_scope_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text("unknown_scope: safe\n")
    with pytest.raises(ValueError, match="unknown_scope"):
        load_policy(path)


def test_deny_has_precedence_over_tool_allowlist() -> None:
    policy = Policy(
        deny={"shell.execute"},
        allow_by_tool={"shell": {"shell.execute"}},
    )
    findings = evaluate_policy([cap("shell.execute", "shell")], policy, 10)
    assert [f.rule_id for f in findings] == ["capability.denied"]
