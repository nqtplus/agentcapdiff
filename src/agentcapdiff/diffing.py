from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ScanResult


def snapshot_payload(result: ScanResult) -> dict[str, Any]:
    return {
        "schema": 1,
        "risk_score": result.risk_score,
        "capabilities": sorted({c.id for c in result.capabilities}),
        "tools": sorted({t.name for t in result.tools}),
    }


def write_snapshot(result: ScanResult, output: Path) -> None:
    output.write_text(json.dumps(snapshot_payload(result), indent=2) + "\n", encoding="utf-8")


def compare_snapshots(base: Path, head: Path) -> dict[str, Any]:
    a = json.loads(base.read_text(encoding="utf-8"))
    b = json.loads(head.read_text(encoding="utf-8"))
    ac, bc = set(a.get("capabilities", [])), set(b.get("capabilities", []))
    at, bt = set(a.get("tools", [])), set(b.get("tools", []))
    return {
        "capabilities_added": sorted(bc - ac),
        "capabilities_removed": sorted(ac - bc),
        "tools_added": sorted(bt - at),
        "tools_removed": sorted(at - bt),
        "risk_delta": int(b.get("risk_score", 0)) - int(a.get("risk_score", 0)),
    }
