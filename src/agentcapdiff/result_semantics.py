from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import TYPE_CHECKING

from .graph import build_capability_graph, capability_graph_to_record
from .policy import Policy, evaluate_policy, policy_to_record
from .schema import capability_to_record
from .scopes import scope_records
from .snapshot_semantics import validate_snapshot_semantics

if TYPE_CHECKING:
    from .models import Finding, ScanResult


class ScanResultConsistencyError(ValueError):
    """Raised when a sealed scanner result no longer matches its semantic evidence."""


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )


def _finding_record(finding: Finding) -> dict[str, object]:
    return {
        "severity": finding.severity,
        "rule_id": finding.rule_id,
        "message": finding.message,
        "capability": finding.capability,
        "tool": finding.tool,
        "source": finding.source,
    }


def _unchecked_output_record(result: ScanResult) -> dict[str, object]:
    return {
        "risk_score": result.risk_score,
        "max_severity": result.max_severity,
        "tools": [
            {
                "name": tool.name,
                "description": tool.description,
                "source": tool.source,
                "adapter": tool.adapter,
            }
            for tool in result.tools
        ],
        "capabilities": [asdict(capability) for capability in result.capabilities],
        "capability_graph": result.capability_graph,
        "policy": result.policy,
        "findings": [asdict(finding) for finding in result.findings],
    }


def _snapshot_projection(result: ScanResult) -> dict[str, object]:
    capability_records = [capability_to_record(capability) for capability in result.capabilities]
    capability_records.sort(
        key=lambda item: (
            str(item.get("id", "")),
            str(item.get("tool", "")),
            str(item.get("source", "")),
        )
    )
    return {
        "capabilities": sorted({capability.id for capability in result.capabilities}),
        "capability_records": capability_records,
        "tools": sorted({tool.name for tool in result.tools}),
        "risk_score": result.risk_score,
        "max_severity": result.max_severity,
        "scopes": scope_records(result.capabilities),
        "capability_graph": result.capability_graph,
        "findings": [_finding_record(finding) for finding in result.findings],
    }


def _semantic_fingerprint(result: ScanResult) -> str:
    payload = _canonical(_unchecked_output_record(result)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _validate_result_projection(result: ScanResult) -> None:
    tool_names = {tool.name for tool in result.tools}
    missing_tools = sorted(
        {
            capability.tool
            for capability in result.capabilities
            if capability.tool not in tool_names
        }
    )
    if missing_tools:
        raise ScanResultConsistencyError(
            "capabilities reference tools absent from discovered tools: "
            + ", ".join(repr(tool) for tool in missing_tools)
        )

    if result.capability_graph is None:
        raise ScanResultConsistencyError("sealed ScanResult requires a capability_graph")
    expected_graph = capability_graph_to_record(build_capability_graph(result.capabilities))
    if _canonical(result.capability_graph) != _canonical(expected_graph):
        raise ScanResultConsistencyError("capability_graph does not match capabilities")

    try:
        validate_snapshot_semantics(_snapshot_projection(result))
    except ValueError as exc:
        raise ScanResultConsistencyError(
            f"ScanResult semantic projection is inconsistent: {exc}"
        ) from exc


def seal_scan_result(result: ScanResult, policy: Policy) -> None:
    """Validate scanner construction and seal the result against later semantic drift."""

    current_fingerprint = getattr(result, "_semantic_fingerprint", None)
    if current_fingerprint is not None:
        assert_scan_result_consistent(result)
        return

    expected_policy = policy_to_record(policy)
    if _canonical(result.policy) != _canonical(expected_policy):
        raise ScanResultConsistencyError(
            "policy record does not match the effective runtime policy"
        )

    expected_findings = evaluate_policy(result.capabilities, policy, result.risk_score)
    if result.findings != expected_findings:
        raise ScanResultConsistencyError("policy findings do not match capabilities and policy")

    _validate_result_projection(result)
    result._semantic_fingerprint = _semantic_fingerprint(result)


def assert_scan_result_consistent(result: ScanResult) -> None:
    """Fail closed if a scanner-sealed result was mutated before serialization.

    Manually constructed, unsealed ScanResult values keep their existing 1.x library
    behavior. Results returned by scan() are sealed and therefore must remain internally
    consistent at every output boundary.
    """

    expected_fingerprint = getattr(result, "_semantic_fingerprint", None)
    if expected_fingerprint is None:
        return

    _validate_result_projection(result)
    current_fingerprint = _semantic_fingerprint(result)
    if current_fingerprint != expected_fingerprint:
        raise ScanResultConsistencyError(
            "sealed ScanResult changed after scanner construction; refusing inconsistent output"
        )
