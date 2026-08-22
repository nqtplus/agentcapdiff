from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import ScanResult
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
    return {
        "schema": 1,
        "risk_score": result.risk_score,
        "max_severity": result.max_severity,
        "capabilities": capability_ids,
        "capability_fingerprint": capability_fingerprint(capability_ids),
        "tools": sorted({t.name for t in result.tools}),
        "scopes": scope_records(result.capabilities),
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
    return {
        "capabilities_added": sorted(bc - ac),
        "capabilities_removed": sorted(ac - bc),
        "tools_added": sorted(bt - at),
        "tools_removed": sorted(at - bt),
        "scope_changes": scope_changes,
        "scope_expansions": scope_expansions,
        "base_risk_score": base_risk,
        "head_risk_score": head_risk,
        "risk_delta": head_risk - base_risk,
        "base_capability_fingerprint": base_fingerprint,
        "head_capability_fingerprint": head_fingerprint,
        "fingerprint_changed": base_fingerprint != head_fingerprint,
        "head_max_severity": str(b.get("max_severity", "INFO")),
        "head_findings": list(b.get("findings", [])),
    }
