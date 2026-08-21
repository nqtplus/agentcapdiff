from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ScanResult


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
    return {
        "schema": 1,
        "risk_score": result.risk_score,
        "max_severity": result.max_severity,
        "capabilities": sorted({c.id for c in result.capabilities}),
        "tools": sorted({t.name for t in result.tools}),
        "findings": _snapshot_findings(result),
    }


def write_snapshot(result: ScanResult, output: Path) -> None:
    output.write_text(
        json.dumps(snapshot_payload(result), indent=2) + "\n",
        encoding="utf-8",
    )


def compare_snapshots(base: Path, head: Path) -> dict[str, Any]:
    a = json.loads(base.read_text(encoding="utf-8"))
    b = json.loads(head.read_text(encoding="utf-8"))
    ac, bc = set(a.get("capabilities", [])), set(b.get("capabilities", []))
    at, bt = set(a.get("tools", [])), set(b.get("tools", []))
    base_risk = int(a.get("risk_score", 0))
    head_risk = int(b.get("risk_score", 0))
    return {
        "capabilities_added": sorted(bc - ac),
        "capabilities_removed": sorted(ac - bc),
        "tools_added": sorted(bt - at),
        "tools_removed": sorted(at - bt),
        "base_risk_score": base_risk,
        "head_risk_score": head_risk,
        "risk_delta": head_risk - base_risk,
        "head_max_severity": str(b.get("max_severity", "INFO")),
        "head_findings": list(b.get("findings", [])),
    }
