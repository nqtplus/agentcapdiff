from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

from .models import Capability, Finding

_POLICY_SCHEMA_VERSION = 1
_MAX_INHERITANCE_DEPTH = 16
_MAPPING_FIELDS = frozenset({"allow_by_tool", "scope_constraints", "trust_boundaries"})
_TRUST_LEVELS = frozenset({"trusted", "untrusted", "unknown"})


@dataclass(frozen=True)
class ScopeConstraint:
    allowed_kinds: frozenset[str] = frozenset({"restricted"})
    allowed_values: tuple[str, ...] = ()


@dataclass(frozen=True)
class TrustBoundary:
    boundary: str
    trust: str = "unknown"
    note: str = ""


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    reason: str
    expires: date
    capability: str | None = None
    tool: str | None = None


@dataclass
class Policy:
    deny: set[str] = field(default_factory=set)
    require_review: set[str] = field(default_factory=set)
    max_risk_score: int = 60
    allow_by_tool: dict[str, set[str]] = field(default_factory=dict)
    scope_constraints: dict[str, ScopeConstraint] = field(default_factory=dict)
    unknown_scope: str = "review"
    trust_boundaries: dict[str, TrustBoundary] = field(default_factory=dict)
    suppressions: tuple[Suppression, ...] = ()
    sources: tuple[str, ...] = ()


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


def _load_trust_boundaries(raw: Any) -> dict[str, TrustBoundary]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("Policy field trust_boundaries must be a mapping")
    result: dict[str, TrustBoundary] = {}
    for tool, config in raw.items():
        if not isinstance(tool, str):
            raise ValueError("Policy trust_boundaries keys must be strings")
        if isinstance(config, str):
            boundary = config
            trust = "unknown"
            note = ""
        elif isinstance(config, dict):
            boundary = config.get("boundary")
            trust = config.get("trust", "unknown")
            note = config.get("note", "")
        else:
            raise ValueError(f"Trust boundary for {tool} must be a string or mapping")
        if not isinstance(boundary, str) or not boundary.strip():
            raise ValueError(f"Trust boundary for {tool} requires a non-empty boundary")
        if trust not in _TRUST_LEVELS:
            raise ValueError(
                f"Trust boundary for {tool} has invalid trust; "
                "expected trusted, untrusted, or unknown"
            )
        if not isinstance(note, str):
            raise ValueError(f"Trust boundary note for {tool} must be a string")
        result[tool] = TrustBoundary(boundary=boundary.strip(), trust=trust, note=note.strip())
    return result


def _load_suppressions(raw: Any, today: date) -> tuple[Suppression, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValueError("Policy field suppressions must be a list")
    result: list[Suppression] = []
    for index, item in enumerate(raw):
        field_name = f"suppressions[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"Policy field {field_name} must be a mapping")
        rule_id = item.get("rule_id")
        reason = item.get("reason")
        expires_raw = item.get("expires")
        if not isinstance(rule_id, str) or not rule_id.strip():
            raise ValueError(f"Policy field {field_name}.rule_id is required")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"Policy field {field_name}.reason is required")
        if isinstance(expires_raw, date) and not isinstance(expires_raw, datetime):
            expires = expires_raw
        elif isinstance(expires_raw, str):
            try:
                expires = date.fromisoformat(expires_raw)
            except ValueError as exc:
                raise ValueError(
                    f"Policy field {field_name}.expires must be YYYY-MM-DD"
                ) from exc
        else:
            raise ValueError(f"Policy field {field_name}.expires must be an ISO date")
        if expires < today:
            raise ValueError(
                f"Policy suppression {rule_id.strip()} expired on {expires.isoformat()}"
            )
        capability = item.get("capability")
        tool = item.get("tool")
        for selector_name, selector in (("capability", capability), ("tool", tool)):
            if selector is not None and (not isinstance(selector, str) or not selector.strip()):
                raise ValueError(
                    f"Policy field {field_name}.{selector_name} must be a non-empty string"
                )
        result.append(
            Suppression(
                rule_id=rule_id.strip(),
                reason=reason.strip(),
                expires=expires,
                capability=capability.strip() if isinstance(capability, str) else None,
                tool=tool.strip() if isinstance(tool, str) else None,
            )
        )
    return tuple(result)


def _merge_raw_policy(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if key == "extends":
            continue
        if key in _MAPPING_FIELDS and isinstance(value, dict) and isinstance(merged.get(key), dict):
            combined = dict(merged[key])
            combined.update(value)
            merged[key] = combined
        else:
            merged[key] = value
    return merged


def _display_source(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _load_raw_policy(
    path: Path,
    root: Path,
    stack: tuple[Path, ...],
) -> tuple[dict[str, Any], list[str]]:
    unresolved = path
    if unresolved.is_symlink():
        raise ValueError(f"Policy inheritance refuses symlinked policy file: {unresolved}")
    resolved = unresolved.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("Inherited policy must stay within the root policy directory") from exc
    if resolved in stack:
        chain = " -> ".join(_display_source(item, root) for item in (*stack, resolved))
        raise ValueError(f"Policy inheritance cycle detected: {chain}")
    if len(stack) >= _MAX_INHERITANCE_DEPTH:
        raise ValueError("Policy inheritance exceeds maximum depth")
    if not resolved.exists():
        raise FileNotFoundError(resolved)

    raw: Any = yaml.safe_load(resolved.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("Policy must be a YAML mapping")

    extends = raw.get("extends", [])
    if isinstance(extends, str):
        extends = [extends]
    if not isinstance(extends, list) or not all(isinstance(item, str) for item in extends):
        raise ValueError("Policy field extends must be a string or list of strings")

    merged: dict[str, Any] = {}
    sources: list[str] = []
    next_stack = (*stack, resolved)
    for parent_ref in extends:
        parent_rel = Path(parent_ref)
        if parent_rel.is_absolute():
            raise ValueError("Policy inheritance does not allow absolute paths")
        parent_path = resolved.parent / parent_rel
        parent_raw, parent_sources = _load_raw_policy(parent_path, root, next_stack)
        merged = _merge_raw_policy(merged, parent_raw)
        for source in parent_sources:
            if source not in sources:
                sources.append(source)

    merged = _merge_raw_policy(merged, raw)
    source = _display_source(resolved, root)
    if source not in sources:
        sources.append(source)
    return merged, sources


def load_policy(path: Path | None, *, today: date | None = None) -> Policy:
    if path is None or not path.exists():
        return Policy()
    current_day = today or datetime.now(UTC).date()
    root = path.resolve().parent
    raw, sources = _load_raw_policy(path, root, ())
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
        trust_boundaries=_load_trust_boundaries(raw.get("trust_boundaries")),
        suppressions=_load_suppressions(raw.get("suppressions"), current_day),
        sources=tuple(sources),
    )


def policy_to_record(policy: Policy) -> dict[str, Any]:
    return {
        "schema": _POLICY_SCHEMA_VERSION,
        "deny": sorted(policy.deny),
        "require_review": sorted(policy.require_review),
        "max_risk_score": policy.max_risk_score,
        "allow_by_tool": {
            tool: sorted(capabilities)
            for tool, capabilities in sorted(policy.allow_by_tool.items())
        },
        "scope_constraints": {
            capability: {
                "allowed_kinds": sorted(constraint.allowed_kinds),
                "allowed_values": list(constraint.allowed_values),
            }
            for capability, constraint in sorted(policy.scope_constraints.items())
        },
        "unknown_scope": policy.unknown_scope,
        "trust_boundaries": {
            tool: {
                "boundary": boundary.boundary,
                "trust": boundary.trust,
                "note": boundary.note,
            }
            for tool, boundary in sorted(policy.trust_boundaries.items())
        },
        "suppressions": [
            {
                "rule_id": suppression.rule_id,
                "capability": suppression.capability,
                "tool": suppression.tool,
                "reason": suppression.reason,
                "expires": suppression.expires.isoformat(),
            }
            for suppression in sorted(
                policy.suppressions,
                key=lambda item: (
                    item.rule_id,
                    item.capability or "",
                    item.tool or "",
                    item.expires.isoformat(),
                    item.reason,
                ),
            )
        ],
        "sources": list(policy.sources),
    }


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


def _suppression_matches(finding: Finding, suppression: Suppression) -> bool:
    if finding.rule_id != suppression.rule_id:
        return False
    if suppression.capability is not None and finding.capability != suppression.capability:
        return False
    return suppression.tool is None or finding.tool == suppression.tool


def _apply_suppressions(findings: list[Finding], policy: Policy) -> list[Finding]:
    if not policy.suppressions:
        return findings
    result: list[Finding] = []
    for finding in findings:
        suppression = next(
            (
                candidate
                for candidate in policy.suppressions
                if _suppression_matches(finding, candidate)
            ),
            None,
        )
        if suppression is None:
            result.append(finding)
            continue
        result.append(
            Finding(
                "INFO",
                "policy.suppressed",
                (
                    f"Suppressed {finding.rule_id} until {suppression.expires.isoformat()}: "
                    f"{suppression.reason}"
                ),
                finding.capability,
                finding.tool,
                finding.source,
            )
        )
    return result


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
    return _apply_suppressions(findings, policy)
