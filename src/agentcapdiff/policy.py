from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Capability, Finding


@dataclass(frozen=True)
class ScopeConstraint:
    allowed_kinds: frozenset[str] = frozenset({"restricted"})
    allowed_values: tuple[str, ...] = ()


@dataclass
class Policy:
    deny: set[str] = field(default_factory=set)
    require_review: set[str] = field(default_factory=set)
    max_risk_score: int = 60
    allow_by_tool: dict[str, set[str]] = field(default_factory=dict)
    scope_constraints: dict[str, ScopeConstraint] = field(default_factory=dict)
    unknown_scope: str = "review"


def _string_set(value: Any, field_name: str) -> set[str]:
    if value is None:
        return set()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Policy field {field_name} must be a list of strings")
    return set(value)


def _load_allow_by_tool(raw: Any) -> dict[str, set[str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("Policy field allow_by_tool must be a mapping")
    result: dict[str, set[str]] = {}
    for tool, capabilities in raw.items():
        if not isinstance(tool, str):
            raise ValueError("Policy allow_by_tool keys must be strings")
        result[tool] = _string_set(capabilities, f"allow_by_tool.{tool}")
    return result


def _load_scope_constraints(raw: Any) -> dict[str, ScopeConstraint]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("Policy field scope_constraints must be a mapping")
    result: dict[str, ScopeConstraint] = {}
    for capability, config in raw.items():
        if not isinstance(capability, str) or not isinstance(config, dict):
            raise ValueError("Each scope constraint must map a capability to a mapping")
        allowed_kinds = _string_set(
            config.get("allowed_kinds", ["restricted"]),
            f"scope_constraints.{capability}.allowed_kinds",
        )
        invalid = allowed_kinds - {"restricted", "broad", "unknown"}
        if invalid:
            raise ValueError(f"Invalid scope kind(s) for {capability}: {sorted(invalid)}")
        allowed_values_raw = config.get("allowed_values", []) or []
        if not isinstance(allowed_values_raw, list) or not all(
            isinstance(item, str) for item in allowed_values_raw
        ):
            field_name = f"scope_constraints.{capability}.allowed_values"
            raise ValueError(f"Policy field {field_name} must be a list of strings")
        result[capability] = ScopeConstraint(
            allowed_kinds=frozenset(allowed_kinds),
            allowed_values=tuple(sorted(set(allowed_values_raw))),
        )
    return result


def load_policy(path: Path | None) -> Policy:
    if path is None or not path.exists():
        return Policy()
    raw: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("Policy must be a YAML mapping")
    unknown_scope = raw.get("unknown_scope", "review")
    if unknown_scope not in {"deny", "review", "ignore"}:
        raise ValueError("Policy unknown_scope must be one of: deny, review, ignore")
    return Policy(
        deny=_string_set(raw.get("deny", []), "deny"),
        require_review=_string_set(raw.get("require_review", []), "require_review"),
        max_risk_score=int(raw.get("max_risk_score", 60)),
        allow_by_tool=_load_allow_by_tool(raw.get("allow_by_tool")),
        scope_constraints=_load_scope_constraints(raw.get("scope_constraints")),
        unknown_scope=unknown_scope,
    )


def _scope_findings(cap: Capability, policy: Policy) -> list[Finding]:
    constraint = policy.scope_constraints.get(cap.id)
    if constraint is None:
        return []

    if cap.scope.kind == "unknown":
        if policy.unknown_scope == "ignore":
            return []
        severity = "HIGH" if policy.unknown_scope == "deny" else "MEDIUM"
        return [
            Finding(
                severity,
                "scope.unknown",
                f"Scope is unknown for constrained capability: {cap.id}",
                cap.id,
                cap.tool,
                cap.source,
            )
        ]

    if cap.scope.kind not in constraint.allowed_kinds:
        return [
            Finding(
                "HIGH",
                "scope.constraint_violation",
                f"Scope kind {cap.scope.kind} is not allowed for capability {cap.id}",
                cap.id,
                cap.tool,
                cap.source,
            )
        ]

    if constraint.allowed_values:
        observed = set(cap.scope.values)
        allowed = set(constraint.allowed_values)
        if not observed or not observed.issubset(allowed):
            return [
                Finding(
                    "HIGH",
                    "scope.value_violation",
                    f"Scope values for {cap.id} exceed the policy allowlist.",
                    cap.id,
                    cap.tool,
                    cap.source,
                )
            ]
    return []


def evaluate_policy(
    capabilities: list[Capability],
    policy: Policy,
    risk_score: int,
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for cap in capabilities:
        key = (cap.id, cap.tool)
        if key in seen:
            continue
        seen.add(key)

        if cap.id in policy.deny:
            findings.append(
                Finding(
                    "HIGH",
                    "capability.denied",
                    f"Denied capability detected: {cap.id}",
                    cap.id,
                    cap.tool,
                    cap.source,
                )
            )
            continue

        allowed = policy.allow_by_tool.get(cap.tool)
        if allowed is not None and cap.id not in allowed:
            findings.append(
                Finding(
                    "HIGH",
                    "capability.tool_allowlist_violation",
                    f"Capability {cap.id} is not allowlisted for tool {cap.tool}.",
                    cap.id,
                    cap.tool,
                    cap.source,
                )
            )
            continue

        scope_findings = _scope_findings(cap, policy)
        findings.extend(scope_findings)
        if any(f.severity == "HIGH" for f in scope_findings):
            continue

        if cap.id in policy.require_review:
            findings.append(
                Finding(
                    "MEDIUM",
                    "capability.review_required",
                    f"Capability requires human review: {cap.id}",
                    cap.id,
                    cap.tool,
                    cap.source,
                )
            )

    if risk_score > policy.max_risk_score:
        findings.append(
            Finding(
                "HIGH",
                "risk.threshold",
                f"Risk score {risk_score} exceeds policy threshold {policy.max_risk_score}.",
            )
        )
    return findings
