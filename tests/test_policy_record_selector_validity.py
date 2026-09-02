import pytest

from agentcapdiff.policy import Policy, ScopeConstraint, policy_to_record


def test_policy_record_rejects_wildcard_deny_selector() -> None:
    with pytest.raises(ValueError, match="wildcard"):
        policy_to_record(Policy(deny={"*"}))


def test_policy_record_rejects_control_format_review_selector() -> None:
    with pytest.raises(ValueError, match="control/format"):
        policy_to_record(Policy(require_review={"github.\u200bwrite"}))


def test_policy_record_rejects_wildcard_allowlist_capability() -> None:
    policy = Policy(allow_by_tool={"repo": {"*"}})

    with pytest.raises(ValueError, match="wildcard"):
        policy_to_record(policy)


def test_policy_record_rejects_colliding_tool_aliases() -> None:
    policy = Policy(
        allow_by_tool={
            "repo-tool": {"filesystem.read"},
            "Repo Tool": {"filesystem.write"},
        }
    )

    with pytest.raises(ValueError, match="ambiguous tool selectors"):
        policy_to_record(policy)


def test_policy_record_rejects_colliding_scope_constraint_aliases() -> None:
    policy = Policy(
        scope_constraints={
            "NETWORK.EXTERNAL": ScopeConstraint(),
            "network.external": ScopeConstraint(),
        }
    )

    with pytest.raises(ValueError, match="colliding capability selectors"):
        policy_to_record(policy)


def test_policy_record_selector_validation_does_not_rewrite_valid_spelling() -> None:
    policy = Policy(
        deny={"SHELL.EXECUTE"},
        require_review={"GITHUB.WRITE"},
        allow_by_tool={"Repo-Tool": {"FILESYSTEM.READ"}},
        scope_constraints={"NETWORK.EXTERNAL": ScopeConstraint()},
    )

    record = policy_to_record(policy)

    assert record["deny"] == ["SHELL.EXECUTE"]
    assert record["require_review"] == ["GITHUB.WRITE"]
    assert record["allow_by_tool"] == {"Repo-Tool": ["FILESYSTEM.READ"]}
    assert "NETWORK.EXTERNAL" in record["scope_constraints"]
