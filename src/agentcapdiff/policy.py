from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import yaml

from .models import Capability, Finding
from .yamlio import safe_load_unique

_POLICY_SCHEMA_VERSION = 1
_MAX_INHERITANCE_DEPTH = 16
_POLICY_MAX_FILE_BYTES = 262_144
_POLICY_MAX_TOTAL_BYTES = 1_048_576
_POLICY_MAX_FILES = 64
_POLICY_MAX_DEPTH = 64
_POLICY_MAX_NODES = 20_000
_MAPPING_FIELDS = frozenset({"allow_by_tool", "scope_constraints", "trust_boundaries"})
_TRUST_LEVELS = frozenset({"trusted", "untrusted", "unknown"})
_UNKNOWN_SCOPE = frozenset({"deny", "review", "ignore"})
_SELECTOR_WILDCARDS = frozenset("*?[]{}")
_IDENTITY_CONTROL_CATEGORIES = frozenset({"Cc", "Cf", "Cs"})
_TOOL_SEPARATOR_RE = re.compile(r"[\s_-]+")
_IDENTITY_SAFETY_RULES = frozenset(
    {"policy.tool_identity_ambiguous", "policy.tool_identity_collision"}
)


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


@dataclass
class _PolicyBudget:
    files: int = 0
    total_bytes: int = 0


def _normalize_identity_text(value: str, field_name: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    if not normalized:
        raise ValueError(f"Policy field {field_name} must be a non-empty string")
    if any(unicodedata.category(char) in _IDENTITY_CONTROL_CATEGORIES for char in normalized):
        raise ValueError(f"Policy field {field_name} contains unsafe control/format characters")
    return normalized


def _reject_wildcard_selector(value: str, field_name: str) -> None:
    if any(char in _SELECTOR_WILDCARDS for char in value):
        raise ValueError(
            f"Policy field {field_name} uses unsupported wildcard selector syntax; "
            "use an explicit selector or omit an optional suppression selector"
        )


def _capability_selector(value: str, field_name: str) -> str:
    normalized = _normalize_identity_text(value, field_name)
    _reject_wildcard_selector(normalized, field_name)
    return normalized


def _rule_selector(value: str, field_name: str) -> str:
    normalized = _normalize_identity_text(value, field_name)
    _reject_wildcard_selector(normalized, field_name)
    return normalized


def _tool_selector(value: str, field_name: str) -> str:
    normalized = _normalize_identity_text(value, field_name)
    normalized = _TOOL_SEPARATOR_RE.sub("_", normalized)
    _reject_wildcard_selector(normalized, field_name)
    return normalized


def _runtime_tool_identity(value: str) -> str | None:
    try:
        return _tool_selector(value, "runtime.tool")
    except ValueError:
        return None


def _string_set(value: Any, field_name: str) -> set[str]:
    if value is None:
        return set()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Policy field {field_name} must be a list of strings")
    return set(value)


def _load_max_risk_score(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
        raise ValueError("Policy field max_risk_score must be an integer from 0 to 100")
    return value


def _load_unknown_scope(value: Any) -> str:
    if not isinstance(value, str) or value not in _UNKNOWN_SCOPE:
        raise ValueError("Policy unknown_scope must be one of: deny, review, ignore")
    return value


def _load_trust_level(value: Any, tool: str) -> str:
    if not isinstance(value, str) or value not in _TRUST_LEVELS:
        raise ValueError(
            f"Trust boundary for {tool} has invalid trust; "
            "expected trusted, untrusted, or unknown"
        )
    return value


def _capability_set(value: Any, field_name: str) -> set[str]:
    if value is None:
        return set()
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"Policy field {field_name} must be a list of strings")
    return {
        _capability_selector(item, f"{field_name}[{index}]")
        for index, item in enumerate(value)
    }


def _canonical_tool_mapping_key(
    tool: str,
    field_name: str,
    seen: dict[str, str],
) -> str:
    canonical = _tool_selector(tool, field_name)
    previous = seen.get(canonical)
    if previous is not None and previous != tool:
        raise ValueError(
            f"Policy field {field_name} contains ambiguous tool selectors "
            f"{previous!r} and {tool!r}"
        )
    seen[canonical] = tool
    return canonical


def _load_allow_by_tool(raw: Any) -> dict[str, set[str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("Policy field allow_by_tool must be a mapping")
    result: dict[str, set[str]] = {}
    seen: dict[str, str] = {}
    for tool, capabilities in raw.items():
        if not isinstance(tool, str):
            raise ValueError("Policy allow_by_tool keys must be strings")
        canonical_tool = _canonical_tool_mapping_key(tool, "allow_by_tool", seen)
        result[canonical_tool] = _capability_set(
            capabilities,
            f"allow_by_tool.{tool}",
        )
    return result


def _load_scope_constraints(raw: Any) -> dict[str, ScopeConstraint]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValueError("Policy field scope_constraints must be a mapping")
    result: dict[str, ScopeConstraint] = {}
    seen: dict[str, str] = {}
    for capability, config in raw.items():
        if not isinstance(capability, str) or not isinstance(config, dict):
            raise ValueError("Each scope constraint must map a capability to a mapping")
        canonical_capability = _capability_selector(capability, "scope_constraints")
        previous = seen.get(canonical_capability)
        if previous is not None and previous != capability:
            raise ValueError(
                "Policy field scope_constraints contains colliding capability selectors "
                f"{previous!r} and {capability!r}"
            )
        seen[canonical_capability] = capability
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
        result[canonical_capability] = ScopeConstraint(
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
    seen: dict[str, str] = {}
    for tool, config in raw.items():
        if not isinstance(tool, str):
            raise ValueError("Policy trust_boundaries keys must be strings")
        canonical_tool = _canonical_tool_mapping_key(tool, "trust_boundaries", seen)
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
        trust = _load_trust_level(trust, tool)
        if not isinstance(note, str):
            raise ValueError(f"Trust boundary note for {tool} must be a string")
        result[canonical_tool] = TrustBoundary(
            boundary=boundary.strip(),
            trust=trust,
            note=note.strip(),
        )
    return result


def _load_suppressions(raw: Any, today: date) -> tuple[Suppression, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValueError("Policy field suppressions must be a list")
    result: list[Suppression] = []
    seen_selectors: set[tuple[str, str | None, str | None]] = set()
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
        canonical_rule = _rule_selector(rule_id, f"{field_name}.rule_id")
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
                f"Policy suppression {canonical_rule} expired on {expires.isoformat()}"
            )
        capability = item.get("capability")
        tool = item.get("tool")
        for selector_name, selector in (("capability", capability), ("tool", tool)):
            if selector is not None and (not isinstance(selector, str) or not selector.strip()):
                raise ValueError(
                    f"Policy field {field_name}.{selector_name} must be a non-empty string"
                )
        canonical_capability = (
            _capability_selector(capability, f"{field_name}.capability")
            if isinstance(capability, str)
            else None
        )
        canonical_tool = (
            _tool_selector(tool, f"{field_name}.tool") if isinstance(tool, str) else None
        )
        selector_key = (canonical_rule, canonical_capability, canonical_tool)
        if selector_key in seen_selectors:
            raise ValueError(f"Policy field {field_name} duplicates a suppression selector")
        seen_selectors.add(selector_key)
        result.append(
            Suppression(
                rule_id=canonical_rule,
                reason=reason.strip(),
                expires=expires,
                capability=canonical_capability,
                tool=canonical_tool,
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


def _validate_policy_structure(value: Any, source: Path) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    visited: set[int] = set()
    nodes = 0

    while stack:
        current, depth = stack.pop()
        if depth > _POLICY_MAX_DEPTH:
            raise ValueError(
                f"Policy nesting exceeds depth limit {_POLICY_MAX_DEPTH}: {source}"
            )
        if not isinstance(current, (dict, list)):
            continue

        object_id = id(current)
        if object_id in visited:
            continue
        visited.add(object_id)
        nodes += 1
        if nodes > _POLICY_MAX_NODES:
            raise ValueError(
                f"Policy structure exceeds node limit {_POLICY_MAX_NODES}: {source}"
            )

        children = current.values() if isinstance(current, dict) else current
        for child in children:
            if isinstance(child, (dict, list)):
                stack.append((child, depth + 1))


def _read_policy_mapping(path: Path, budget: _PolicyBudget) -> dict[str, Any]:
    budget.files += 1
    if budget.files > _POLICY_MAX_FILES:
        raise ValueError(f"Policy inheritance exceeds file limit {_POLICY_MAX_FILES}")

    try:
        with path.open("rb") as handle:
            payload = handle.read(_POLICY_MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise ValueError(f"Policy file cannot be read safely: {path}") from exc

    if len(payload) > _POLICY_MAX_FILE_BYTES:
        raise ValueError(
            f"Policy file exceeds {_POLICY_MAX_FILE_BYTES} byte limit: {path}"
        )
    new_total = budget.total_bytes + len(payload)
    if new_total > _POLICY_MAX_TOTAL_BYTES:
        raise ValueError(
            f"Policy input exceeds total byte limit {_POLICY_MAX_TOTAL_BYTES}: {path}"
        )
    budget.total_bytes = new_total

    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"Policy file is not valid UTF-8: {path}") from exc

    try:
        raw: Any = safe_load_unique(text) or {}
    except (yaml.YAMLError, RecursionError) as exc:
        raise ValueError(
            f"Policy YAML is malformed or exceeds parser safety limits: {path}"
        ) from exc

    _validate_policy_structure(raw, path)
    if not isinstance(raw, dict):
        raise ValueError("Policy must be a YAML mapping")
    return raw


def _load_raw_policy(
    path: Path,
    root: Path,
    stack: tuple[Path, ...],
    budget: _PolicyBudget,
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

    raw = _read_policy_mapping(resolved, budget)

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
        parent_raw, parent_sources = _load_raw_policy(parent_path, root, next_stack, budget)
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
    raw, sources = _load_raw_policy(path, root, (), _PolicyBudget())
    unknown_scope = _load_unknown_scope(raw.get("unknown_scope", "review"))
    return Policy(
        deny=_capability_set(raw.get("deny", []), "deny"),
        require_review=_capability_set(raw.get("require_review", []), "require_review"),
        max_risk_score=_load_max_risk_score(raw.get("max_risk_score", 60)),
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


def _canonical_scope_constraints(policy: Policy) -> dict[str, ScopeConstraint]:
    result: dict[str, ScopeConstraint] = {}
    seen: dict[str, str] = {}
    for capability, constraint in policy.scope_constraints.items():
        raw = str(capability)
        canonical = _capability_selector(raw, "scope_constraints")
        previous = seen.get(canonical)
        if previous is not None and previous != raw:
            raise ValueError(
                "Policy field scope_constraints contains colliding capability selectors "
                f"{previous!r} and {raw!r}"
            )
        seen[canonical] = raw
        result[canonical] = constraint
    return result


def _scope_findings(
    cap: Capability,
    cap_id: str,
    scope_constraints: dict[str, ScopeConstraint],
    policy: Policy,
) -> list[Finding]:
    constraint = scope_constraints.get(cap_id)
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


def _canonical_policy_allowlists(policy: Policy) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    seen: dict[str, str] = {}
    for tool, capabilities in policy.allow_by_tool.items():
        canonical_tool = _canonical_tool_mapping_key(str(tool), "allow_by_tool", seen)
        result[canonical_tool] = {
            _capability_selector(str(capability), f"allow_by_tool.{tool}")
            for capability in capabilities
        }
    return result


def _canonical_suppressions(policy: Policy) -> tuple[Suppression, ...]:
    result: list[Suppression] = []
    seen: set[tuple[str, str | None, str | None]] = set()
    for suppression in policy.suppressions:
        rule_id = _rule_selector(suppression.rule_id, "suppression.rule_id")
        capability = (
            _capability_selector(suppression.capability, "suppression.capability")
            if suppression.capability is not None
            else None
        )
        tool = (
            _tool_selector(suppression.tool, "suppression.tool")
            if suppression.tool is not None
            else None
        )
        selector = (rule_id, capability, tool)
        if selector in seen:
            raise ValueError("Policy contains duplicate canonical suppression selectors")
        seen.add(selector)
        result.append(
            Suppression(
                rule_id=rule_id,
                reason=suppression.reason,
                expires=suppression.expires,
                capability=capability,
                tool=tool,
            )
        )
    return tuple(result)


def _tool_identity_findings(
    capabilities: list[Capability],
    targeted_tools: set[str],
) -> tuple[list[Finding], set[str]]:
    if not targeted_tools:
        return [], set()

    raw_by_identity: dict[str, set[str]] = {}
    ambiguous_raw: set[str] = set()
    for cap in capabilities:
        identity = _runtime_tool_identity(cap.tool)
        if identity is None:
            ambiguous_raw.add(cap.tool)
            continue
        raw_by_identity.setdefault(identity, set()).add(cap.tool)
        normalized_text = unicodedata.normalize("NFKC", cap.tool).strip()
        if any(ord(char) > 127 for char in normalized_text) and identity not in targeted_tools:
            ambiguous_raw.add(cap.tool)

    findings: list[Finding] = []
    blocked_identities: set[str] = set()
    for identity, raw_names in sorted(raw_by_identity.items()):
        if len(raw_names) > 1 and identity in targeted_tools:
            blocked_identities.add(identity)
            names = ", ".join(repr(name) for name in sorted(raw_names))
            findings.append(
                Finding(
                    "HIGH",
                    "policy.tool_identity_collision",
                    f"Multiple tool names collapse to policy identity {identity!r}: {names}",
                )
            )

    for raw_name in sorted(ambiguous_raw):
        findings.append(
            Finding(
                "HIGH",
                "policy.tool_identity_ambiguous",
                f"Tool identity cannot be matched safely to configured selectors: {raw_name!r}",
                tool=raw_name,
            )
        )
    return findings, blocked_identities


def _suppression_matches(finding: Finding, suppression: Suppression) -> bool:
    if finding.rule_id in _IDENTITY_SAFETY_RULES:
        return False
    if _rule_selector(finding.rule_id, "finding.rule_id") != suppression.rule_id:
        return False
    if suppression.capability is not None:
        if finding.capability is None:
            return False
        if _capability_selector(finding.capability, "finding.capability") != suppression.capability:
            return False
    if suppression.tool is None:
        return True
    if finding.tool is None:
        return False
    identity = _runtime_tool_identity(finding.tool)
    return identity is not None and identity == suppression.tool


def _apply_suppressions(
    findings: list[Finding],
    suppressions: tuple[Suppression, ...],
) -> list[Finding]:
    if not suppressions:
        return findings
    result: list[Finding] = []
    for finding in findings:
        suppression = next(
            (
                candidate
                for candidate in suppressions
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
    allow_by_tool = _canonical_policy_allowlists(policy)
    scope_constraints = _canonical_scope_constraints(policy)
    suppressions = _canonical_suppressions(policy)
    targeted_tools = set(allow_by_tool)
    targeted_tools.update(
        suppression.tool for suppression in suppressions if suppression.tool is not None
    )
    identity_findings, blocked_identities = _tool_identity_findings(capabilities, targeted_tools)
    findings.extend(identity_findings)

    deny = {_capability_selector(capability, "deny") for capability in policy.deny}
    require_review = {
        _capability_selector(capability, "require_review")
        for capability in policy.require_review
    }
    seen: set[tuple[str, str]] = set()
    for cap in capabilities:
        cap_id = _capability_selector(cap.id, "capability.id")
        tool_identity = _runtime_tool_identity(cap.tool)
        identity_key = tool_identity if tool_identity is not None else f"raw:{cap.tool}"
        key = (cap_id, identity_key)
        if key in seen:
            continue
        seen.add(key)

        if cap_id in deny:
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

        if tool_identity is not None and tool_identity in blocked_identities:
            continue

        if tool_identity is not None:
            allowed = allow_by_tool.get(tool_identity)
            if allowed is not None and cap_id not in allowed:
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

        scope_findings = _scope_findings(
            cap,
            cap_id,
            scope_constraints,
            policy,
        )
        findings.extend(scope_findings)
        if any(f.severity == "HIGH" for f in scope_findings):
            continue

        if cap_id in require_review:
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
    return _apply_suppressions(findings, suppressions)
