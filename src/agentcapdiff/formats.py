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

    policy = result.policy or {}
    sources = policy.get("sources", []) if isinstance(policy, dict) else []
    if len(sources) > 1:
        lines.append("\nEffective policy inheritance:")
        lines.extend(f"  - {source}" for source in sources)
    boundaries = policy.get("trust_boundaries", {}) if isinstance(policy, dict) else {}
    if isinstance(boundaries, dict) and boundaries:
        lines.append("\nTrust-boundary annotations (review context only):")
        for tool, annotation in sorted(boundaries.items()):
            if not isinstance(annotation, dict):
                continue
            boundary = annotation.get("boundary", "unknown")
            trust = annotation.get("trust", "unknown")
            lines.append(f"  - {tool}: {boundary} / trust={trust}")
    suppressions = policy.get("suppressions", []) if isinstance(policy, dict) else []
    if isinstance(suppressions, list) and suppressions:
        lines.append("\nActive policy suppressions:")
        for item in suppressions:
            if not isinstance(item, dict):
                continue
            selector = "/".join(
                str(item.get(key) or "*") for key in ("rule_id", "capability", "tool")
            )
            expiry = item.get("expires", "")
            reason = item.get("reason", "")
            lines.append(f"  - {selector} until {expiry}: {reason}")

    graph = result.capability_graph or {}
    paths = graph.get("paths", []) if isinstance(graph, dict) else []
    if paths:
        lines.append("\nPossible capability paths (static evidence only):")
        for path in paths:
            severity = str(path.get("severity", "INFO"))
            confidence = str(path.get("confidence", "low"))
            title = str(path.get("title", "Possible capability path"))
            lines.append(f"  [{severity}/{confidence}] {title}")
        lines.append("  Runtime reachability/exploitability is not established by these paths.")

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


def _markdown_path(path: dict[str, Any]) -> str:
    severity = _markdown_escape(path.get("severity", "INFO"))
    confidence = _markdown_escape(path.get("confidence", "low"))
    title = _markdown_escape(path.get("title", "Possible capability path"))
    capabilities = " + ".join(
        f"`{_markdown_escape(value)}`" for value in path.get("capabilities", [])
    )
    tools = ", ".join(f"`{_markdown_escape(value)}`" for value in path.get("tools", []))
    tool_evidence = f" Tools: {tools}." if tools else ""
    return (
        f"- **{severity}** / confidence **{confidence}** — {title}: {capabilities}."
        f"{tool_evidence} Static evidence only; runtime reachability/exploitability "
        "is not established."
    )


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

    policy_changed = bool(diff.get("policy_changed", False))
    base_policy_fingerprint = str(diff.get("base_policy_fingerprint", ""))
    head_policy_fingerprint = str(diff.get("head_policy_fingerprint", ""))
    if base_policy_fingerprint and head_policy_fingerprint:
        lines.append(
            "**Policy fingerprint:** "
            f"`{base_policy_fingerprint[:12]}` → `{head_policy_fingerprint[:12]}`"
        )

    sections = (
        ("Capabilities added", diff.get("capabilities_added", [])),
        ("Capabilities removed", diff.get("capabilities_removed", [])),
        ("Tools added", diff.get("tools_added", [])),
        ("Tools removed", diff.get("tools_removed", [])),
    )
    has_change = policy_changed
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

    paths_added = list(diff.get("paths_added", []))
    if paths_added:
        has_change = True
        lines.extend(["", "### New possible capability paths"])
        lines.extend(_markdown_path(path) for path in paths_added)

    policy_warnings = list(diff.get("policy_weakening_warnings", []))
    if policy_warnings:
        has_change = True
        lines.extend(["", "### ⚠️ Policy weakening warnings"])
        for warning in policy_warnings:
            message = _markdown_escape(warning.get("message", "Policy became less restrictive."))
            lines.append(f"- **REVIEW REQUIRED** — {message}")

    head_policy = diff.get("head_policy")
    if policy_changed and isinstance(head_policy, dict):
        boundaries = head_policy.get("trust_boundaries", {})
        if isinstance(boundaries, dict) and boundaries:
            lines.extend(["", "### Effective trust-boundary annotations"])
            for tool, annotation in sorted(boundaries.items()):
                if not isinstance(annotation, dict):
                    continue
                boundary = _markdown_escape(annotation.get("boundary", "unknown"))
                trust = _markdown_escape(annotation.get("trust", "unknown"))
                lines.append(f"- `{_markdown_escape(tool)}`: {boundary} / trust **{trust}**")
        suppressions = head_policy.get("suppressions", [])
        if isinstance(suppressions, list) and suppressions:
            lines.extend(["", "### Active temporary suppressions"])
            for item in suppressions:
                if not isinstance(item, dict):
                    continue
                rule_id = _markdown_escape(item.get("rule_id", ""))
                capability = _markdown_escape(item.get("capability") or "*")
                tool = _markdown_escape(item.get("tool") or "*")
                expires = _markdown_escape(item.get("expires", ""))
                reason = _markdown_escape(item.get("reason", ""))
                lines.append(
                    f"- `{rule_id}` / `{capability}` / `{tool}` until **{expires}** — {reason}"
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
                "No capability, tool, or effective-policy changes detected. "
                "No static scope or possible-path changes detected.",
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
