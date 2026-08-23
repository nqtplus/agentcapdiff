from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from .models import (
    UNIVERSAL_CAPABILITY_SCHEMA_VERSION,
    Capability,
    CapabilityEvidence,
    ScopeEvidence,
)

VALID_CONFIDENCE = {"low", "medium", "high"}
VALID_SCOPE_KINDS = {"restricted", "broad", "unknown"}


def capability_to_record(capability: Capability) -> dict[str, Any]:
    """Serialize one capability into the framework-neutral schema."""
    return {
        "schema_version": capability.schema_version,
        "id": capability.id,
        "tool": capability.tool,
        "risk": capability.risk,
        "reason": capability.reason,
        "source": capability.source,
        "scope": {
            "kind": capability.scope.kind,
            "values": list(capability.scope.values),
            "reason": capability.scope.reason,
        },
        "evidence": [
            {
                "adapter": item.adapter,
                "source": item.source,
                "signal": item.signal,
            }
            for item in capability.evidence
        ],
        "confidence": capability.confidence,
    }


def capability_from_record(record: dict[str, Any]) -> Capability:
    """Parse a schema record conservatively; unsupported uncertainty stays unknown."""
    version = str(record.get("schema_version", ""))
    if version != UNIVERSAL_CAPABILITY_SCHEMA_VERSION:
        raise ValueError(f"unsupported capability schema version: {version or '(missing)'}")

    raw_scope = record.get("scope")
    scope_data = raw_scope if isinstance(raw_scope, dict) else {}
    scope_kind = str(scope_data.get("kind", "unknown"))
    if scope_kind not in VALID_SCOPE_KINDS:
        scope_kind = "unknown"
    values = scope_data.get("values", [])
    if not isinstance(values, list):
        values = []
    scope = ScopeEvidence(
        kind=scope_kind,
        values=tuple(sorted(str(value) for value in values)),
        reason=str(
            scope_data.get(
                "reason",
                "Static input does not establish an effective scope.",
            )
        ),
    )

    evidence_items: list[CapabilityEvidence] = []
    raw_evidence = record.get("evidence", [])
    if isinstance(raw_evidence, list):
        for item in raw_evidence:
            if not isinstance(item, dict):
                continue
            evidence_items.append(
                CapabilityEvidence(
                    adapter=str(item.get("adapter", "generic")),
                    source=str(item.get("source", "")),
                    signal=str(item.get("signal", "Static metadata evidence.")),
                )
            )

    confidence = str(record.get("confidence", "low"))
    if confidence not in VALID_CONFIDENCE:
        confidence = "low"

    return Capability(
        id=str(record.get("id", "")),
        tool=str(record.get("tool", "")),
        risk=int(record.get("risk", 0)),
        reason=str(record.get("reason", "")),
        source=str(record.get("source", "")),
        scope=scope,
        evidence=tuple(evidence_items),
        confidence=confidence,
        schema_version=version,
    )


def canonical_capabilities_json(capabilities: Iterable[Capability]) -> str:
    """Return deterministic canonical JSON suitable for conformance checks."""
    records = [capability_to_record(capability) for capability in capabilities]
    records.sort(
        key=lambda item: (
            str(item.get("id", "")),
            str(item.get("tool", "")),
            str(item.get("source", "")),
        )
    )
    return json.dumps(
        {
            "schema_version": UNIVERSAL_CAPABILITY_SCHEMA_VERSION,
            "capabilities": records,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
