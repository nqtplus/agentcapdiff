from datetime import date
from pathlib import Path

import pytest

from agentcapdiff.models import Capability
from agentcapdiff.policy import Policy, Suppression, evaluate_policy, load_policy


def _cap(capability: str, tool: str) -> Capability:
    return Capability(id=capability, tool=tool, risk=10, reason="test")


def test_tool_allowlist_matches_case_nfkc_and_separator_aliases(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text(
        "allow_by_tool:\n"
        "  ' Repo-Tool ':\n"
        "    - FILESYSTEM.READ\n",
        encoding="utf-8",
    )
    policy = load_policy(path)
    assert policy.allow_by_tool == {"repo_tool": {"filesystem.read"}}

    findings = evaluate_policy([_cap("filesystem.write", "ＲＥＰＯ TOOL")], policy, 10)
    assert [finding.rule_id for finding in findings] == [
        "capability.tool_allowlist_violation"
    ]
    assert findings[0].severity == "HIGH"


def test_capability_selectors_are_nfkc_casefolded(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text(
        "deny:\n"
        "  - ＳＨＥＬＬ.ＥＸＥＣＵＴＥ\n"
        "require_review:\n"
        "  - GITHUB.WRITE\n",
        encoding="utf-8",
    )
    policy = load_policy(path)
    assert policy.deny == {"shell.execute"}
    assert policy.require_review == {"github.write"}
    findings = evaluate_policy(
        [_cap("shell.execute", "shell"), _cap("github.write", "repo")],
        policy,
        10,
    )
    assert {finding.rule_id for finding in findings} == {
        "capability.denied",
        "capability.review_required",
    }


def test_duplicate_capability_aliases_canonicalize_deterministically(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text(
        "deny:\n"
        "  - SHELL.EXECUTE\n"
        "  - shell.execute\n"
        "  - ＳＨＥＬＬ.ＥＸＥＣＵＴＥ\n",
        encoding="utf-8",
    )
    assert load_policy(path).deny == {"shell.execute"}


def test_inherited_tool_selector_alias_collision_fails_closed(tmp_path: Path) -> None:
    base = tmp_path / "base.yml"
    child = tmp_path / "policy.yml"
    base.write_text(
        "allow_by_tool:\n  repo-tool:\n    - filesystem.read\n",
        encoding="utf-8",
    )
    child.write_text(
        "extends: base.yml\n"
        "allow_by_tool:\n  'Repo Tool':\n    - filesystem.write\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="ambiguous tool selectors"):
        load_policy(child)


@pytest.mark.parametrize(
    "payload, match",
    [
        ("allow_by_tool:\n  '   ': [filesystem.read]\n", "non-empty"),
        ("allow_by_tool:\n  '*': [filesystem.read]\n", "wildcard"),
        ("trust_boundaries:\n  '?': internet\n", "wildcard"),
        ("scope_constraints:\n  '*': {allowed_kinds: [restricted]}\n", "wildcard"),
    ],
)
def test_empty_or_wildcard_policy_selectors_are_rejected(
    tmp_path: Path,
    payload: str,
    match: str,
) -> None:
    path = tmp_path / "policy.yml"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(ValueError, match=match):
        load_policy(path)


def test_suppression_tool_selector_uses_same_canonical_identity(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text(
        "require_review:\n  - shell.execute\n"
        "suppressions:\n"
        "  - rule_id: CAPABILITY.REVIEW_REQUIRED\n"
        "    capability: SHELL.EXECUTE\n"
        "    tool: Repo-Tool\n"
        "    reason: reviewed migration\n"
        "    expires: 2026-09-30\n",
        encoding="utf-8",
    )
    policy = load_policy(path, today=date(2026, 8, 29))
    findings = evaluate_policy([_cap("shell.execute", "repo tool")], policy, 10)
    assert [finding.rule_id for finding in findings] == ["policy.suppressed"]


def test_duplicate_canonical_suppression_selectors_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text(
        "suppressions:\n"
        "  - rule_id: capability.review_required\n"
        "    tool: repo-tool\n"
        "    reason: first\n"
        "    expires: 2026-09-30\n"
        "  - rule_id: CAPABILITY.REVIEW_REQUIRED\n"
        "    tool: 'Repo Tool'\n"
        "    reason: second\n"
        "    expires: 2026-10-01\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicates a suppression selector"):
        load_policy(path, today=date(2026, 8, 29))


def test_wildcard_suppression_tool_is_rejected_use_omission_for_any(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text(
        "suppressions:\n"
        "  - rule_id: capability.review_required\n"
        "    tool: '*'\n"
        "    reason: migration\n"
        "    expires: 2026-09-30\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="wildcard"):
        load_policy(path, today=date(2026, 8, 29))


def test_unicode_confusable_unmatched_tool_identity_fails_closed() -> None:
    policy = Policy(allow_by_tool={"repo_tool": {"filesystem.read"}})
    # Cyrillic small ie (U+0435) visually resembles ASCII e.
    findings = evaluate_policy([_cap("filesystem.write", "rеpo_tool")], policy, 10)
    assert [finding.rule_id for finding in findings] == [
        "policy.tool_identity_ambiguous"
    ]
    assert findings[0].severity == "HIGH"


def test_canonical_tool_collision_is_high_and_not_suppressible() -> None:
    policy = Policy(
        allow_by_tool={"repo_tool": {"filesystem.read"}},
        suppressions=(
            Suppression(
                rule_id="policy.tool_identity_collision",
                reason="should not suppress identity safety",
                expires=date(2030, 1, 1),
            ),
        ),
    )
    findings = evaluate_policy(
        [
            _cap("filesystem.read", "repo-tool"),
            _cap("filesystem.write", "Repo Tool"),
        ],
        policy,
        10,
    )
    assert [finding.rule_id for finding in findings] == [
        "policy.tool_identity_collision"
    ]
    assert findings[0].severity == "HIGH"


def test_control_format_character_in_policy_tool_selector_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "policy.yml"
    path.write_text(
        "allow_by_tool:\n  'repo\u200b_tool': [filesystem.read]\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="control/format"):
        load_policy(path)


def test_unsafe_runtime_tool_identity_cannot_bypass_global_deny() -> None:
    policy = Policy(deny={"shell.execute"})
    findings = evaluate_policy([_cap("shell.execute", "shell\u200b")], policy, 10)
    assert [finding.rule_id for finding in findings] == ["capability.denied"]
    assert findings[0].severity == "HIGH"


def test_direct_policy_scope_constraint_uses_canonical_capability_identity() -> None:
    from agentcapdiff.models import ScopeEvidence
    from agentcapdiff.policy import ScopeConstraint

    policy = Policy(
        scope_constraints={"NETWORK.EXTERNAL": ScopeConstraint()},
        unknown_scope="deny",
    )
    capability = Capability(
        id="network.external",
        tool="fetch",
        risk=10,
        reason="test",
        scope=ScopeEvidence(kind="unknown"),
    )
    findings = evaluate_policy([capability], policy, 10)
    assert [finding.rule_id for finding in findings] == ["scope.unknown"]
    assert findings[0].severity == "HIGH"
