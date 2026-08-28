from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import UNIVERSAL_CAPABILITY_SCHEMA_VERSION, ScanResult
from .outputio import atomic_write_text
from .schema import capability_to_record
from .scopes import scope_is_expansion, scope_records
from .snapshotio import DEFAULT_SNAPSHOT_LIMITS, SnapshotLimits, load_snapshot


def capability_fingerprint(capabilities: Iterable[str]) -> str:
    """Return a stable SHA-256 fingerprint of the normalized capability surface."""
    canonical = {
        "schema": 1,
        "capabilities": sorted(set(capabilities)),
    }
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _snapshot_findings(result: ScanResult) -> list[dict[str, Any]]:
    findings = [
        {
            "severity": finding.severity,
            "rule_id": finding.rule_id,
            "message": finding.message,
            "capability": finding.capability,
            "tool": finding.tool,
        }
        for finding in result.findings
    ]
    return sorted(
        findings,
        key=lambda item: (
            str(item.get("severity", "")),
            str(item.get("rule_id", "")),
            str(item.get("capability", "")),
            str(item.get("tool", "")),
        ),
    )


def snapshot_payload(result: ScanResult) -> dict[str, Any]:
    capability_ids = sorted({c.id for c in result.capabilities})
    capability_records = [capability_to_record(cap) for cap in result.capabilities]
    capability_records.sort(
        key=lambda item: (
            str(item.get("id", "")),
            str(item.get("tool", "")),
            str(item.get("source", "")),
        )
    )
    return {
        "schema": 1,
        "capability_schema_version": UNIVERSAL_CAPABILITY_SCHEMA_VERSION,
        "risk_score": result.risk_score,
        "max_severity": result.max_severity,
        "capabilities": capability_ids,
        "capability_records": capability_records,
        "capability_fingerprint": capability_fingerprint(capability_ids),
        "tools": sorted({t.name for t in result.tools}),
        "scopes": scope_records(result.capabilities),
        "capability_graph": result.capability_graph,
        "policy": result.policy,
        "findings": _snapshot_findings(result),
    }


def write_snapshot(result: ScanResult, output: Path) -> None:
    atomic_write_text(
        output,
        json.dumps(snapshot_payload(result), indent=2) + "\n",
    )


def _snapshot_fingerprint(snapshot: dict[str, Any]) -> str:
    stored = snapshot.get("capability_fingerprint")
    if isinstance(stored, str) and len(stored) == 64:
        return stored
    capabilities = (str(value) for value in snapshot.get("capabilities", []))
    return capability_fingerprint(capabilities)


def _scope_map(snapshot: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for item in snapshot.get("scopes", []):
        if not isinstance(item, dict):
            continue
        capability = str(item.get("capability", ""))
        tool = str(item.get("tool", ""))
        if capability and tool:
            result[(capability, tool)] = {
                "kind": str(item.get("kind", "unknown")),
                "values": sorted(str(v) for v in item.get("values", [])),
                "reason": str(item.get("reason", "")),
            }
    return result


def _scope_changes(
    a: dict[str, Any],
    b: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    base = _scope_map(a)
    head = _scope_map(b)
    changes: list[dict[str, Any]] = []
    expansions: list[dict[str, Any]] = []
    for key in sorted(set(base) | set(head)):
        before = base.get(key, {"kind": "unknown", "values": [], "reason": ""})
        after = head.get(key, {"kind": "unknown", "values": [], "reason": ""})
        if before == after:
            continue
        item = {
            "capability": key[0],
            "tool": key[1],
            "before": before,
            "after": after,
        }
        changes.append(item)
        if scope_is_expansion(before, after):
            expansions.append(item)
    return changes, expansions


def _path_records(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    graph = snapshot.get("capability_graph")
    if not isinstance(graph, dict):
        return []
    paths = graph.get("paths")
    if not isinstance(paths, list):
        return []
    return [item for item in paths if isinstance(item, dict) and item.get("id")]


def _policy_record(snapshot: dict[str, Any]) -> dict[str, Any] | None:
    policy = snapshot.get("policy")
    return policy if isinstance(policy, dict) else None


def _canonical_policy(policy: dict[str, Any] | None) -> dict[str, Any]:
    if policy is None:
        return {
            "schema": 1,
            "deny": [],
            "require_review": [],
            "max_risk_score": 60,
            "allow_by_tool": {},
            "scope_constraints": {},
            "unknown_scope": "review",
            "trust_boundaries": {},
            "suppressions": [],
        }
    return {
        "schema": int(policy.get("schema", 1)),
        "deny": sorted(str(value) for value in policy.get("deny", [])),
        "require_review": sorted(str(value) for value in policy.get("require_review", [])),
        "max_risk_score": int(policy.get("max_risk_score", 60)),
        "allow_by_tool": {
            str(tool): sorted(str(value) for value in values)
            for tool, values in sorted(policy.get("allow_by_tool", {}).items())
        },
        "scope_constraints": {
            str(capability): {
                "allowed_kinds": sorted(
                    str(value) for value in constraint.get("allowed_kinds", [])
                ),
                "allowed_values": sorted(
                    str(value) for value in constraint.get("allowed_values", [])
                ),
            }
            for capability, constraint in sorted(policy.get("scope_constraints", {}).items())
            if isinstance(constraint, dict)
        },
        "unknown_scope": str(policy.get("unknown_scope", "review")),
        "trust_boundaries": {
            str(tool): {
                "boundary": str(annotation.get("boundary", "unknown")),
                "trust": str(annotation.get("trust", "unknown")),
                "note": str(annotation.get("note", "")),
            }
            for tool, annotation in sorted(policy.get("trust_boundaries", {}).items())
            if isinstance(annotation, dict)
        },
        "suppressions": sorted(
            (
                {
                    "rule_id": str(item.get("rule_id", "")),
                    "capability": item.get("capability"),
                    "tool": item.get("tool"),
                    "reason": str(item.get("reason", "")),
                    "expires": str(item.get("expires", "")),
                }
                for item in policy.get("suppressions", [])
                if isinstance(item, dict)
            ),
            key=lambda item: (
                str(item.get("rule_id", "")),
                str(item.get("capability") or ""),
                str(item.get("tool") or ""),
                str(item.get("expires", "")),
                str(item.get("reason", "")),
            ),
        ),
    }


def policy_fingerprint(policy: dict[str, Any] | None) -> str:
    canonical = _canonical_policy(policy)
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _warning(kind: str, message: str, **details: Any) -> dict[str, Any]:
    return {"kind": kind, "message": message, **details}


def _policy_weakening_warnings(
    base_policy: dict[str, Any] | None,
    head_policy: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    if base_policy is None:
        return []
    base = _canonical_policy(base_policy)
    head = _canonical_policy(head_policy)
    warnings: list[dict[str, Any]] = []

    base_deny = set(base["deny"])
    head_deny = set(head["deny"])
    for capability in sorted(base_deny - head_deny):
        warnings.append(
            _warning(
                "deny_removed",
                f"Global deny removed for capability {capability}.",
                capability=capability,
            )
        )

    base_review = set(base["require_review"])
    head_review = set(head["require_review"])
    for capability in sorted(base_review - head_review):
        warnings.append(
            _warning(
                "review_requirement_removed",
                f"Review requirement removed for capability {capability}.",
                capability=capability,
            )
        )

    if int(head["max_risk_score"]) > int(base["max_risk_score"]):
        warnings.append(
            _warning(
                "risk_threshold_raised",
                "Maximum allowed risk score increased.",
                before=base["max_risk_score"],
                after=head["max_risk_score"],
            )
        )

    scope_order = {"deny": 0, "review": 1, "ignore": 2}
    if scope_order.get(str(head["unknown_scope"]), 1) > scope_order.get(
        str(base["unknown_scope"]), 1
    ):
        warnings.append(
            _warning(
                "unknown_scope_weakened",
                "Unknown-scope handling became less restrictive.",
                before=base["unknown_scope"],
                after=head["unknown_scope"],
            )
        )

    base_allow = base["allow_by_tool"]
    head_allow = head["allow_by_tool"]
    for tool in sorted(set(base_allow) | set(head_allow)):
        before = set(base_allow.get(tool, []))
        after = set(head_allow.get(tool, []))
        added = sorted(after - before)
        if added:
            warnings.append(
                _warning(
                    "tool_allowlist_expanded",
                    f"Per-tool allowlist expanded for {tool}: {', '.join(added)}.",
                    tool=tool,
                    capabilities=added,
                )
            )

    base_constraints = base["scope_constraints"]
    head_constraints = head["scope_constraints"]
    for capability in sorted(set(base_constraints) | set(head_constraints)):
        before = base_constraints.get(capability)
        after = head_constraints.get(capability)
        if before is None:
            continue
        if after is None:
            warnings.append(
                _warning(
                    "scope_constraint_removed",
                    f"Scope constraint removed for capability {capability}.",
                    capability=capability,
                )
            )
            continue
        before_kinds = set(before.get("allowed_kinds", []))
        after_kinds = set(after.get("allowed_kinds", []))
        added_kinds = sorted(after_kinds - before_kinds)
        if added_kinds:
            warnings.append(
                _warning(
                    "scope_kind_expanded",
                    f"Allowed scope kinds expanded for {capability}: {', '.join(added_kinds)}.",
                    capability=capability,
                    values=added_kinds,
                )
            )
        before_values = set(before.get("allowed_values", []))
        after_values = set(after.get("allowed_values", []))
        added_values = sorted(after_values - before_values)
        if added_values:
            warnings.append(
                _warning(
                    "scope_values_expanded",
                    f"Allowed scope values expanded for {capability}: {', '.join(added_values)}.",
                    capability=capability,
                    values=added_values,
                )
            )

    base_suppressions = {
        (
            item["rule_id"],
            item.get("capability"),
            item.get("tool"),
            item["expires"],
        )
        for item in base["suppressions"]
    }
    head_suppressions = {
        (
            item["rule_id"],
            item.get("capability"),
            item.get("tool"),
            item["expires"],
        )
        for item in head["suppressions"]
    }
    for item in sorted(head_suppressions - base_suppressions, key=str):
        rule_id, capability, tool, expires = item
        warnings.append(
            _warning(
                "suppression_added",
                "Temporary policy suppression added; review the exception and expiry.",
                rule_id=rule_id,
                capability=capability,
                tool=tool,
                expires=expires,
            )
        )

    base_boundaries = base["trust_boundaries"]
    head_boundaries = head["trust_boundaries"]
    for tool in sorted(base_boundaries.keys() - head_boundaries.keys()):
        warnings.append(
            _warning(
                "trust_boundary_removed",
                f"Trust-boundary annotation removed for tool {tool}; review context was reduced.",
            )
        )
    return warnings


def compare_snapshots(
    base: Path,
    head: Path,
    *,
    limits: SnapshotLimits = DEFAULT_SNAPSHOT_LIMITS,
) -> dict[str, Any]:
    a = load_snapshot(base, limits)
    b = load_snapshot(head, limits)
    ac, bc = set(a.get("capabilities", [])), set(b.get("capabilities", []))
    at, bt = set(a.get("tools", [])), set(b.get("tools", []))
    base_risk = int(a.get("risk_score", 0))
    head_risk = int(b.get("risk_score", 0))
    base_fingerprint = _snapshot_fingerprint(a)
    head_fingerprint = _snapshot_fingerprint(b)
    scope_changes, scope_expansions = _scope_changes(a, b)
    base_paths = {str(item["id"]): item for item in _path_records(a)}
    head_paths = {str(item["id"]): item for item in _path_records(b)}
    added_path_ids = sorted(head_paths.keys() - base_paths.keys())
    removed_path_ids = sorted(base_paths.keys() - head_paths.keys())
    base_policy = _policy_record(a)
    head_policy = _policy_record(b)
    base_policy_fingerprint = policy_fingerprint(base_policy)
    head_policy_fingerprint = policy_fingerprint(head_policy)
    return {
        "capabilities_added": sorted(bc - ac),
        "capabilities_removed": sorted(ac - bc),
        "tools_added": sorted(bt - at),
        "tools_removed": sorted(at - bt),
        "base_risk_score": base_risk,
        "head_risk_score": head_risk,
        "risk_delta": head_risk - base_risk,
        "head_max_severity": str(b.get("max_severity", "INFO")),
        "head_findings": b.get("findings", []),
        "base_capability_fingerprint": base_fingerprint,
        "head_capability_fingerprint": head_fingerprint,
        "fingerprint_changed": base_fingerprint != head_fingerprint,
        "scope_changes": scope_changes,
        "scope_expansions": scope_expansions,
        "paths_added": [head_paths[path_id] for path_id in added_path_ids],
        "paths_removed": [base_paths[path_id] for path_id in removed_path_ids],
        "base_policy_fingerprint": base_policy_fingerprint,
        "head_policy_fingerprint": head_policy_fingerprint,
        "policy_changed": base_policy_fingerprint != head_policy_fingerprint,
        "policy_weakening_warnings": _policy_weakening_warnings(base_policy, head_policy),
        "head_policy": head_policy,
    }
