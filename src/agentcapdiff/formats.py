from __future__ import annotations

import json
from pathlib import Path

from .models import ScanResult


def text_report(result: ScanResult) -> str:
    lines = [
        "AgentCapDiff",
        "============",
        f"Tools inspected: {len(result.tools)}",
        f"Capabilities: {len({c.id for c in result.capabilities})}",
        f"Risk score: {result.risk_score}/100",
    ]
    if result.capabilities:
        lines.append("\nCapability inventory:")
        for cap_id in sorted({c.id for c in result.capabilities}):
            tools = sorted({c.tool for c in result.capabilities if c.id == cap_id})
            lines.append(f"  - {cap_id}: {', '.join(tools)}")
    if result.findings:
        lines.append("\nFindings:")
        for finding in result.findings:
            lines.append(f"  [{finding.severity}] {finding.message}")
    else:
        lines.append("\nNo policy violations detected.")
    return "\n".join(lines)


def json_report(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True)


def sarif_report(result: ScanResult) -> str:
    rules = {}
    sarif_results = []
    for finding in result.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.rule_id.replace(".", " ").title()},
        }
        level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}.get(finding.severity, "note")
        item = {"ruleId": finding.rule_id, "level": level, "message": {"text": finding.message}}
        if finding.source:
            try:
                uri = Path(finding.source).as_posix()
            except Exception:
                uri = finding.source
            item["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
        sarif_results.append(item)
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "AgentCapDiff", "rules": list(rules.values())}},
            "results": sarif_results,
        }],
    }
    return json.dumps(payload, indent=2)
