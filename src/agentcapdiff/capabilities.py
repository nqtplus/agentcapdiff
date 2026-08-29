from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .models import Capability, CapabilityEvidence, ToolRecord
from .scopes import scope_for_capability


@dataclass(frozen=True)
class CapabilityRule:
    id: str
    risk: int
    patterns: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class SchemaSignals:
    properties: frozenset[str] = frozenset()
    action_values: frozenset[str] = frozenset()
    text: str = ""


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

ACTION_PROPERTIES = {"action", "operation", "mode", "method"}
ACTION_LITERAL_KEYS = {"const", "enum", "default", "examples"}
SHELL_PROPERTIES = {"argv", "cmd", "command", "script", "shell", "shell_command"}
PATH_PROPERTIES = {
    "base_path",
    "dir",
    "directory",
    "file",
    "file_path",
    "filepath",
    "path",
    "paths",
    "root",
    "source_path",
}
WRITE_PAYLOAD_PROPERTIES = {"body", "bytes", "content", "contents", "data", "payload", "text"}
EXPLICIT_WRITE_PROPERTIES = {
    "destination_path",
    "output_file",
    "output_path",
    "target_path",
    "write_path",
}
EXPLICIT_READ_PROPERTIES = {"input_file", "input_path", "read_path", "source_file"}
NETWORK_PROPERTIES = {
    "base_url",
    "endpoint",
    "endpoints",
    "remote_url",
    "request_url",
    "webhook_url",
}
MAIL_DESTINATION_PROPERTIES = {"recipient", "recipients", "to"}
MAIL_BODY_PROPERTIES = {"body", "html", "message", "subject", "text"}
REPOSITORY_PROPERTIES = {"repo", "repository", "repository_name", "repository_url"}
FILESYSTEM_MUTATIONS = {"create", "delete", "remove", "save", "update", "write"}
GITHUB_MUTATIONS = {"create", "delete", "merge", "push", "update"}
SEND_ACTIONS = {"send"}


def _normalize_label(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    value = re.sub(r"[^A-Za-z0-9]+", "_", value)
    return value.strip("_").lower()


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for part in value for item in _strings(part)]
    return []


def _schema_signals(schema: dict[str, Any] | None) -> SchemaSignals:
    if not schema:
        return SchemaSignals()

    properties: set[str] = set()
    action_values: set[str] = set()
    text: list[str] = []
    stack: list[tuple[Any, str | None]] = [(schema, None)]
    seen: set[int] = set()

    while stack:
        current, context = stack.pop()
        if not isinstance(current, (dict, list)):
            continue
        object_id = id(current)
        if object_id in seen:
            continue
        seen.add(object_id)

        if isinstance(current, list):
            stack.extend((item, context) for item in current if isinstance(item, (dict, list)))
            continue

        for key, value in current.items():
            key_l = str(key).lower()
            if key_l == "properties" and isinstance(value, dict):
                for name, child in value.items():
                    normalized = _normalize_label(str(name))
                    if normalized:
                        properties.add(normalized)
                    if isinstance(child, (dict, list)):
                        stack.append((child, normalized or context))
                continue
            if key_l in {"title", "description"} and isinstance(value, str):
                text.append(value)
            if context in ACTION_PROPERTIES and key_l in ACTION_LITERAL_KEYS:
                action_values.update(_normalize_label(item) for item in _strings(value))
            if isinstance(value, (dict, list)):
                stack.append((value, context))

    return SchemaSignals(
        properties=frozenset(properties),
        action_values=frozenset(value for value in action_values if value),
        text=" ".join(text).lower(),
    )


def _schema_property_matches(rule_id: str, signals: SchemaSignals) -> tuple[str, ...]:
    props = signals.properties
    actions = signals.action_values
    matched: set[str] = set()

    if rule_id == "shell.execute":
        matched.update(f"property:{name}" for name in props & SHELL_PROPERTIES)
    elif rule_id == "secrets.access":
        for name in props:
            if re.search(r"(?:^|_)(?:secret|credential|api_key|token|password)(?:_|$)", name):
                matched.add(f"property:{name}")
    elif rule_id == "filesystem.write":
        explicit = props & EXPLICIT_WRITE_PROPERTIES
        matched.update(f"property:{name}" for name in explicit)
        if props & PATH_PROPERTIES and props & WRITE_PAYLOAD_PROPERTIES:
            matched.add("property-combination:path+payload")
        if props & PATH_PROPERTIES and actions & FILESYSTEM_MUTATIONS:
            matched.add("action:path+filesystem-mutation")
    elif rule_id == "filesystem.read":
        explicit = props & EXPLICIT_READ_PROPERTIES
        matched.update(f"property:{name}" for name in explicit)
        write_like = bool(
            props & EXPLICIT_WRITE_PROPERTIES
            or (props & PATH_PROPERTIES and props & WRITE_PAYLOAD_PROPERTIES)
            or (props & PATH_PROPERTIES and actions & FILESYSTEM_MUTATIONS)
        )
        if props & PATH_PROPERTIES and not write_like:
            matched.add("property:path-like")
    elif rule_id == "network.external":
        matched.update(f"property:{name}" for name in props & NETWORK_PROPERTIES)
    elif rule_id == "email.send":
        if props & MAIL_DESTINATION_PROPERTIES and props & MAIL_BODY_PROPERTIES:
            matched.add("property-combination:recipient+message")
        if props & MAIL_DESTINATION_PROPERTIES and actions & SEND_ACTIONS:
            matched.add("action:recipient+send")
    elif rule_id == "github.write":
        if props & REPOSITORY_PROPERTIES and actions & GITHUB_MUTATIONS:
            matched.add("action:repository+mutation")

    return tuple(sorted(matched))


def infer_capabilities(tools: list[ToolRecord]) -> list[Capability]:
    out: list[Capability] = []
    for tool in tools:
        haystack = f"{tool.name} {tool.description}".lower()
        schema_signals = _schema_signals(tool.input_schema)
        for rule in RULES:
            matched = tuple(
                pattern
                for pattern in rule.patterns
                if re.search(pattern, haystack, flags=re.IGNORECASE)
            )
            schema_text = tuple(
                pattern
                for pattern in rule.patterns
                if schema_signals.text
                and re.search(pattern, schema_signals.text, flags=re.IGNORECASE)
            )
            schema_properties = _schema_property_matches(rule.id, schema_signals)
            if not matched and not schema_text and not schema_properties:
                continue

            adapter = tool.adapter or "generic"
            confidence = "medium" if matched and adapter in RECOGNIZED_STATIC_ADAPTERS else "low"
            evidence_parts: list[str] = []
            if matched:
                evidence_parts.append("name/description matched: " + ", ".join(matched))
            if schema_text:
                evidence_parts.append("schema text matched: " + ", ".join(schema_text))
            if schema_properties:
                evidence_parts.append("schema signal: " + ", ".join(schema_properties))

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
                            signal="; ".join(evidence_parts),
                        ),
                    ),
                    confidence=confidence,
                )
            )
    return out
