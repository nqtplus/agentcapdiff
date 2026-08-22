from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any

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
        scoped = [
            c
            for c in result.capabilities
            if c.id.startswith("filesystem.") or c.id == "network.external"
        ]
        if scoped:
            lines.append("\nStatic scope evidence:")
            for cap in sorted(scoped, key=lambda c: (c.id, c.tool)):
                values = ", ".join(cap.scope.values) if cap.scope.values else "(not established)"
                lines.append(f"  - {cap.id}/{cap.tool}: {cap.scope.kind} — {values}")
    if result.findings:
        lines.append("\nFindings:")
        for finding in result.findings:
            lines.append(f"  [{finding.severity}] {finding.message}")
    else:
        lines.append("\nNo policy violations detected.")
    return "\n".join(lines)


def json_report(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True)


def _markdown_escape(value: object) -> str:
    text = html.escape(str(value), quote=False)
    text = text.replace("\r", " ").replace("\n", " ")
    special = (
        "\\",
        "`",
        "*",
        "_",
        "{",
        "}",
        "[",
        "]",
        "(",
        ")",
        "#",
        "+",
        "|",
        "!",
    )
    for char in special:
        text = text.replace(char, f"\\{char}")
    return text


def _scope_label(scope: dict[str, Any]) -> str:
    kind = _markdown_escape(scope.get("kind", "unknown"))
    values = [_markdown_escape(v) for v in scope.get("values", [])]
    return f"{kind}: {', '.join(values) if values else '(not established)'}"


def markdown_diff_report(diff: dict[str, Any]) -> str:
    base_risk = int(diff.get("base_risk_score", 0))
    head_risk = int(diff.get("head_risk_score", 0))
    delta = int(diff.get("risk_delta", head_risk - base_risk))
    delta_text = f"+{delta}" if delta > 0 else str(delta)
    lines = [
        "## AgentCapDiff capability change",
        "",
        f"**Risk score:** {base_risk}/100 → {head_risk}/100 ({delta_text})",
    ]

    base_fingerprint = str(diff.get("base_capability_fingerprint", ""))
    head_fingerprint = str(diff.get("head_capability_fingerprint", ""))
    if base_fingerprint and head_fingerprint:
        lines.append(
            "**Capability fingerprint:** "
            f"`{base_fingerprint[:12]}` → `{head_fingerprint[:12]}`"
        )

    sections = (
        ("Capabilities added", diff.get("capabilities_added", [])),
        ("Capabilities removed", diff.get("capabilities_removed", [])),
        ("Tools added", diff.get("tools_added", [])),
        ("Tools removed", diff.get("tools_removed", [])),
    )
    has_change = False
    for title, values in sections:
        if not values:
            continue
        has_change = True
        lines.extend(["", f"### {title}"])
        lines.extend(f"- `{_markdown_escape(value)}`" for value in values)

    scope_changes = list(diff.get("scope_changes", []))
    if scope_changes:
        has_change = True
        lines.extend(["", "### Scope changes"])
        expansion_keys = {
            (str(item.get("capability", "")), str(item.get("tool", "")))
            for item in diff.get("scope_expansions", [])
        }
        for item in scope_changes:
            capability = _markdown_escape(item.get("capability", ""))
            tool = _markdown_escape(item.get("tool", ""))
            marker = " **EXPANSION**" if (
                str(item.get("capability", "")), str(item.get("tool", ""))
            ) in expansion_keys else ""
            lines.append(
                f"- `{capability}` / `{tool}`{marker}: "
                f"{_scope_label(item.get('before', {}))} → "
                f"{_scope_label(item.get('after', {}))}"
            )

    findings = list(diff.get("head_findings", []))
    if findings:
        lines.extend(["", "### Policy findings in PR head"])
        for finding in findings:
            severity = _markdown_escape(finding.get("severity", "INFO"))
            message = _markdown_escape(finding.get("message", "Policy finding"))
            lines.append(f"- **{severity}** — {message}")

    if not has_change:
        lines.extend(
            [
                "",
                "No capability or tool changes detected. "
                "No static scope changes detected.",
            ]
        )
    return "\n".join(lines)


def sarif_report(result: ScanResult) -> str:
    rules = {}
    sarif_results = []
    levels = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
        "INFO": "note",
    }
    for finding in result.findings:
        rules[finding.rule_id] = {
            "id": finding.rule_id,
            "shortDescription": {"text": finding.rule_id.replace(".", " ").title()},
        }
        level = levels.get(finding.severity, "note")
        item = {
            "ruleId": finding.rule_id,
            "level": level,
            "message": {"text": finding.message},
        }
        if finding.source:
            try:
                uri = Path(finding.source).as_posix()
            except Exception:
                uri = finding.source
        else:
            uri = "agentcapdiff.yaml"
        item["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": uri}}}
        ]
        sarif_results.append(item)
    payload = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AgentCapDiff",
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(payload, indent=2)
