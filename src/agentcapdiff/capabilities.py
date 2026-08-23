from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Capability, CapabilityEvidence, ToolRecord
from .scopes import scope_for_capability


@dataclass(frozen=True)
class CapabilityRule:
    id: str
    risk: int
    patterns: tuple[str, ...]
    reason: str


RULES = (
    CapabilityRule(
        "shell.execute",
        35,
        (r"\bshell\b", r"\bexec(?:ute)?\b", r"terminal", r"command"),
        "Can execute operating-system commands.",
    ),
    CapabilityRule(
        "filesystem.write",
        25,
        (
            r"write[_ -]?file",
            r"create[_ -]?file",
            r"delete[_ -]?file",
            r"filesystem.*write",
            r"save[_ -]?file",
        ),
        "Can modify local files.",
    ),
    CapabilityRule(
        "filesystem.read",
        10,
        (r"read[_ -]?file", r"filesystem.*read", r"load[_ -]?file"),
        "Can read local files.",
    ),
    CapabilityRule(
        "network.external",
        15,
        (r"http", r"fetch", r"request", r"browser", r"web"),
        "Can communicate with external network resources.",
    ),
    CapabilityRule(
        "secrets.access",
        35,
        (r"secret", r"credential", r"api[_ -]?key", r"token", r"password"),
        "May access credentials or secrets.",
    ),
    CapabilityRule(
        "email.send",
        25,
        (r"send[_ -]?(?:email|mail)", r"gmail.*send", r"smtp"),
        "Can send messages externally.",
    ),
    CapabilityRule(
        "github.write",
        20,
        (
            r"github.*(?:create|update|delete|merge|push)",
            r"create[_ -]?pull",
            r"merge[_ -]?pull",
            r"push[_ -]?commit",
        ),
        "Can mutate GitHub state.",
    ),
)

RECOGNIZED_STATIC_ADAPTERS = {
    "openai",
    "openai-agents",
    "mcp",
    "claude",
    "langchain",
    "langgraph",
    "crewai",
}


def infer_capabilities(tools: list[ToolRecord]) -> list[Capability]:
    out: list[Capability] = []
    for tool in tools:
        haystack = f"{tool.name} {tool.description}".lower()
        for rule in RULES:
            matched = tuple(
                pattern
                for pattern in rule.patterns
                if re.search(pattern, haystack, flags=re.IGNORECASE)
            )
            if matched:
                adapter = tool.adapter or "generic"
                confidence = "medium" if adapter in RECOGNIZED_STATIC_ADAPTERS else "low"
                out.append(
                    Capability(
                        id=rule.id,
                        tool=tool.name,
                        risk=rule.risk,
                        reason=rule.reason,
                        source=tool.source,
                        scope=scope_for_capability(rule.id, tool),
                        evidence=(
                            CapabilityEvidence(
                                adapter=adapter,
                                source=tool.source,
                                signal="name/description matched: " + ", ".join(matched),
                            ),
                        ),
                        confidence=confidence,
                    )
                )
    return out
