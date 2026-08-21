from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Capability, Finding


@dataclass
class Policy:
    deny: set[str] = field(default_factory=set)
    require_review: set[str] = field(default_factory=set)
    max_risk_score: int = 60


def load_policy(path: Path | None) -> Policy:
    if path is None or not path.exists():
        return Policy()
    raw: Any = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("Policy must be a YAML mapping")
    return Policy(
        deny=set(raw.get("deny", []) or []),
        require_review=set(raw.get("require_review", []) or []),
        max_risk_score=int(raw.get("max_risk_score", 60)),
    )


def evaluate_policy(capabilities: list[Capability], policy: Policy, risk_score: int) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for cap in capabilities:
        key = (cap.id, cap.tool)
        if key in seen:
            continue
        seen.add(key)
        if cap.id in policy.deny:
            findings.append(Finding("HIGH", "capability.denied", f"Denied capability detected: {cap.id}", cap.id, cap.tool, cap.source))
        elif cap.id in policy.require_review:
            findings.append(Finding("MEDIUM", "capability.review_required", f"Capability requires human review: {cap.id}", cap.id, cap.tool, cap.source))
    if risk_score > policy.max_risk_score:
        findings.append(Finding("HIGH", "risk.threshold", f"Risk score {risk_score} exceeds policy threshold {policy.max_risk_score}."))
    return findings
