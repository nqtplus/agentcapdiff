from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import UNIVERSAL_CAPABILITY_SCHEMA_VERSION, ScanResult
from .schema import capability_to_record
from .scopes import scope_is_expansion, scope_records


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
    output.write_text(
        json.dumps(snapshot_payload(result), indent=2) + "\n",
        encoding="utf-8",
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
    paths = graph.get("paths", [])
    if not isinstance(paths, list):
        return []
    return [item for item in paths if isinstance(item, dict) and item.get("id")]


def _policy_record(snapshot: dict[str, Any]) -> dict[str, Any] | None:
    policy = snapshot.get("policy")
    return policy if isinstance(policy, dict) else None


def _policy_semantics(policy: dict[str, Any]) -> dict[str, Any]:
    semantic = dict(policy)
    semantic.pop("sources", None)
    return semantic


def _policy_fingerprint(policy: dict[str, Any] | None) -> str:
    if policy is None:
        return ""
    encoded = json.dumps(
        _policy_semantics(policy),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _record_string_set(value: Any) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(item) for item in value}


def _record_mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {str(key): item for key, item in value.items()}


def _warning(kind: str, message: str) -> dict[str, str]:
    return {"kind": kind, "message": message}


def _allowlist_weakening(base: dict[str, Any], head: dict[str, Any]) -> list[dict[str, str]]:
    warnings: list[dict[str, str]] = []
    base_map = _record_mapping(base.get("allow_by_tool"))
    head_map = _record_mapping(head.get("allow_by_tool"))
    for tool, before_raw in sorted(base_map.items()):
        before = _record_string_set(before_raw)
        if tool not in head_map:
            warnings.append(
                _warning(
                    "tool_allowlist_removed",
                    f"Per-tool capability allowlist removed for {tool}.",
                )
            )
            continue
        after = _record_string_set(head_map[tool])
        for capability in sorted(after - before):
            warnings.append(
                _warning(
                    "tool_allowlist_expanded",
                    f"Tool {tool} newly allows capability {capability}.",
                )
            )
    return warnings


def _scope_constraint_weakening(
    base: dict[str, Any], head: dict[str, Any]
) -> list[dict[str, str]]:
    warnings: list[dict[str, str]] = []
    base_map = _record_mapping(base.get("scope_constraints"))
    head_map = _record_mapping(head.get("scope_constraints"))
    for capability, before_raw in sorted(base_map.items()):
        if capability not in head_map:
            warnings.append(
                _warning(
                    "scope_constraint_removed",
                    f"Scope constraint removed for capability {capability}.",
                )
            )
            continue
        before = _record_mapping(before_raw)
        after = _record_mapping(head_map[capability])
        before_kinds = _record_string_set(before.get("allowed_kinds"))
        after_kinds = _record_string_set(after.get("allowed_kinds"))
        for kind in sorted(after_kinds - before_kinds):
            warnings.append(
                _warning(
                    "scope_kind_expanded",
                    f"Scope constraint for {capability} newly allows kind {kind}.",
                )
            )
        before_values = _record_string_set(before.get("allowed_values"))
        after_values = _record_string_set(after.get("allowed_values"))
        if before_values and not after_values:
            warnings.append(
                _warning(
                    "scope_values_unconstrained",
                    f"Scope value allowlist removed for capability {capability}.",
                )
            )
        elif before_values and after_values:
            for value in sorted(after_values - before_values):
                warnings.append(
                    _warning(
                        "scope_values_expanded",
                        f"Scope constraint for {capability} newly allows value {value}.",
                    )
                )
    return warnings


def _suppression_key(item: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(item.get("rule_id", "")),
        str(item.get("capability") or ""),
        str(item.get("tool") or ""),
    )


def _suppression_weakening(base: dict[str, Any], head: dict[str, Any]) -> list[dict[str, str]]:
    warnings: list[dict[str, str]] = []
    base_items = [item for item in base.get("suppressions", []) if isinstance(item, dict)]
    head_items = [item for item in head.get("suppressions", []) if isinstance(item, dict)]
    base_by_key = {_suppression_key(item): item for item in base_items}
    for item in head_items:
        key = _suppression_key(item)
        selector = "/".join(part or "*" for part in key)
        before = base_by_key.get(key)
        if before is None:
            warnings.append(
                _warning(
                    "suppression_added",
                    f"Temporary policy suppression added for {selector} until {item.get('expires', '')}.",
                )
            )
            continue
        if str(item.get("expires", "")) > str(before.get("expires", "")):
            warnings.append(
                _warning(
                    "suppression_extended",
                    f"Policy suppression for {selector} was extended to {item.get('expires', '')}.",
                )
            )
    return warnings


def _policy_weakening_warnings(
    base: dict[str, Any] | None,
    head: dict[str, Any] | None,
) -> list[dict[str, str]]:
    if base is None or head is None:
        return []
    warnings: list[dict[str, str]] = []

    for capability in sorted(
        _record_string_set(base.get("deny")) - _record_string_set(head.get("deny"))
    ):
        warnings.append(
            _warning("deny_removed", f"Global deny removed for capability {capability}.")
        )
    for capability in sorted(
        _record_string_set(base.get("require_review"))
        - _record_string_set(head.get("require_review"))
    ):
        warnings.append(
            _warning(
                "review_requirement_removed",
                f"Human-review requirement removed for capability {capability}.",
            )
        )

    try:
        base_risk = int(base.get("max_risk_score", 60))
        head_risk = int(head.get("max_risk_score", 60))
    except (TypeError, ValueError):
        base_risk = head_risk = 60
    if head_risk > base_risk:
        warnings.append(
            _warning(
                "risk_threshold_raised",
                f"Maximum allowed risk score increased from {base_risk} to {head_risk}.",
            )
        )

    unknown_order = {"ignore": 0, "review": 1, "deny": 2}
    before_unknown = str(base.get("unknown_scope", "review"))
    after_unknown = str(head.get("unknown_scope", "review"))
    if unknown_order.get(after_unknown, 1) < unknown_order.get(before_unknown, 1):
        warnings.append(
            _warning(
                "unknown_scope_weakened",
                f"Unknown-scope handling weakened from {before_unknown} to {after_unknown}.",
            )
        )

    warnings.extend(_allowlist_weakening(base, head))
    warnings.extend(_scope_constraint_weakening(base, head))
    warnings.extend(_suppression_weakening(base, head))

    base_boundaries = _record_mapping(base.get("trust_boundaries"))
    head_boundaries = _record_mapping(head.get("trust_boundaries"))
    for tool in sorted(base_boundaries.keys() - head_boundaries.keys()):
        warnings.append(
            _warning(
                "trust_boundary_removed",
                f"Trust-boundary annotation removed for tool {tool}; review context was reduced.",
            )
        )
    return warnings


def compare_snapshots(base: Path, head: Path) -> dict[str, Any]:
    a = json.loads(base.read_text(encoding="utf-8"))
    b = json.loads(head.read_text(encoding="utf-8"))
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
    base_policy_fingerprint = _policy_fingerprint(base_policy)
    head_policy_fingerprint = _policy_fingerprint(head_policy)
    return {
        "capabilities_added": sorted(bc - ac),
        "capabilities_removed": sorted(ac - bc),
        "tools_added": sorted(bt - at),
        "tools_removed": sorted(at - bt),
        "scope_changes": scope_changes,
        "scope_expansions": scope_expansions,
        "paths_added": [head_paths[path_id] for path_id in added_path_ids],
        "paths_removed": [base_paths[path_id] for path_id in removed_path_ids],
        "head_paths": [head_paths[path_id] for path_id in sorted(head_paths)],
        "base_risk_score": base_risk,
        "head_risk_score": head_risk,
        "risk_delta": head_risk - base_risk,
        "base_capability_fingerprint": base_fingerprint,
        "head_capability_fingerprint": head_fingerprint,
        "fingerprint_changed": base_fingerprint != head_fingerprint,
        "base_policy_fingerprint": base_policy_fingerprint,
        "head_policy_fingerprint": head_policy_fingerprint,
        "policy_changed": bool(
            base_policy_fingerprint
            and head_policy_fingerprint
            and base_policy_fingerprint != head_policy_fingerprint
        ),
        "policy_weakening_warnings": _policy_weakening_warnings(base_policy, head_policy),
        "head_policy": head_policy,
        "head_max_severity": str(b.get("max_severity", "INFO")),
        "head_findings": list(b.get("findings", [])),
    }
