from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolRecord:
    name: str
    description: str = ""
    source: str = ""


@dataclass(frozen=True)
class Capability:
    id: str
    tool: str
    risk: int
    reason: str
    source: str = ""


@dataclass(frozen=True)
class Finding:
    severity: str
    rule_id: str
    message: str
    capability: str | None = None
    tool: str | None = None
    source: str = ""


@dataclass
class ScanResult:
    tools: list[ToolRecord] = field(default_factory=list)
    capabilities: list[Capability] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        if not self.capabilities:
            return 0
        unique = {}
        for cap in self.capabilities:
            unique[cap.id] = max(unique.get(cap.id, 0), cap.risk)
        return min(100, sum(unique.values()))

    @property
    def max_severity(self) -> str:
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return max(
            (f.severity for f in self.findings),
            key=lambda x: order.get(x, 0),
            default="INFO",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "max_severity": self.max_severity,
            "tools": [asdict(x) for x in self.tools],
            "capabilities": [asdict(x) for x in self.capabilities],
            "findings": [asdict(x) for x in self.findings],
        }
