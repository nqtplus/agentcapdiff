from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import UTC, date, datetime
from math import isfinite
from typing import TYPE_CHECKING

from .capabilities import infer_capabilities
from .graph import build_capability_graph, capability_graph_to_record
from .policy import (
    Policy,
    ScopeConstraint,
    Suppression,
    TrustBoundary,
    evaluate_policy,
    policy_to_record,
)
from .schema import capability_to_record
from .scope_reconcile import reconcile_capability_scopes
from .scopes import scope_records
from .snapshot_semantics import validate_snapshot_semantics

if TYPE_CHECKING:
    from .models import Finding, ScanResult

_UNKNOWN_SCOPE = frozenset({"deny", "review", "ignore"})
_TRUST_LEVELS = frozenset({"trusted", "untrusted", "unknown"})
_SCOPE_KINDS = frozenset({"restricted", "broad", "unknown"})
_COLLECTION_TYPES = (list, tuple, set, frozenset)


class ScanResultConsistencyError(ValueError):
    """Raised when a sealed scanner result no longer matches its semantic evidence."""


def _utc_today() -> date:
    return datetime.now(UTC).date()


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _validate_json_compatible(value: object, path: str, active: set[int]) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not isfinite(value):
            raise ScanResultConsistencyError(
                f"{path} contains a non-finite number that is not valid JSON"
            )
        return

    if isinstance(value, dict):
        object_id = id(value)
        if object_id in active:
            raise ScanResultConsistencyError(
                f"{path} contains a cyclic mapping that is not valid JSON"
            )
        active.add(object_id)
        try:
            for key, child in value.items():
                if not isinstance(key, str):
                    raise ScanResultConsistencyError(
                        f"{path} contains a non-string mapping key that is not valid JSON"
                    )
                _validate_json_compatible(child, f"{path}.{key}", active)
        except RecursionError as exc:
            raise ScanResultConsistencyError(
                f"{path} exceeds safe JSON-compatible nesting"
            ) from exc
        finally:
            active.remove(object_id)
        return

    if isinstance(value, list):
        object_id = id(value)
        if object_id in active:
            raise ScanResultConsistencyError(
                f"{path} contains a cyclic sequence that is not valid JSON"
            )
        active.add(object_id)
        try:
            for index, child in enumerate(value):
                _validate_json_compatible(child, f"{path}[{index}]", active)
        except RecursionError as exc:
            raise ScanResultConsistencyError(
                f"{path} exceeds safe JSON-compatible nesting"
            ) from exc
        finally:
            active.remove(object_id)
        return

    raise ScanResultConsistencyError(
        f"{path} contains unsupported {type(value).__name__} evidence; "
        "tool input schemas must be strict JSON-compatible data"
    )


def _validate_tool_schemas(result: ScanResult) -> None:
    for index, tool in enumerate(result.tools):
        if tool.input_schema is None:
            continue
        _validate_json_compatible(
            tool.input_schema,
            f"tools[{index}].input_schema",
            set(),
        )


def _validate_string_collection(
    value: object,
    field_name: str,
    *,
    allow_empty_strings: bool = False,
) -> None:
    if not isinstance(value, _COLLECTION_TYPES):
        raise ScanResultConsistencyError(
            f"effective policy {field_name} must be a collection of strings"
        )
    for item in value:
        if not isinstance(item, str) or (not allow_empty_strings and not item.strip()):
            raise ScanResultConsistencyError(
                f"effective policy {field_name} must contain strings"
            )


def _validate_effective_policy(policy: Policy) -> None:
    _validate_string_collection(policy.deny, "deny")
    _validate_string_collection(policy.require_review, "require_review")

    threshold = policy.max_risk_score
    if (
        isinstance(threshold, bool)
        or not isinstance(threshold, int)
        or not 0 <= threshold <= 100
    ):
        raise ScanResultConsistencyError(
            "effective policy max_risk_score must be an integer from 0 to 100"
        )

    allow_by_tool = policy.allow_by_tool
    if not isinstance(allow_by_tool, dict):
        raise ScanResultConsistencyError(
            "effective policy allow_by_tool must be a mapping"
        )
    for tool, capabilities in allow_by_tool.items():
        if not isinstance(tool, str) or not tool.strip():
            raise ScanResultConsistencyError(
                "effective policy allow_by_tool keys must be non-empty strings"
            )
        _validate_string_collection(capabilities, f"allow_by_tool.{tool}")

    constraints = policy.scope_constraints
    if not isinstance(constraints, dict):
        raise ScanResultConsistencyError(
            "effective policy scope_constraints must be a mapping"
        )
    for capability, constraint in constraints.items():
        if not isinstance(capability, str) or not capability.strip():
            raise ScanResultConsistencyError(
                "effective policy scope_constraints keys must be non-empty strings"
            )
        if not isinstance(constraint, ScopeConstraint):
            raise ScanResultConsistencyError(
                "effective policy scope constraint for "
                f"{capability!r} must be a ScopeConstraint"
            )
        _validate_string_collection(
            constraint.allowed_kinds,
            f"scope_constraints.{capability}.allowed_kinds",
        )
        if not set(constraint.allowed_kinds).issubset(_SCOPE_KINDS):
            raise ScanResultConsistencyError(
                f"effective policy scope constraint for {capability!r} has invalid kind"
            )
        _validate_string_collection(
            constraint.allowed_values,
            f"scope_constraints.{capability}.allowed_values",
            allow_empty_strings=True,
        )

    unknown_scope = policy.unknown_scope
    if not isinstance(unknown_scope, str) or unknown_scope not in _UNKNOWN_SCOPE:
        raise ScanResultConsistencyError(
            "effective policy unknown_scope must be deny, review, or ignore"
        )

    boundaries = policy.trust_boundaries
    if not isinstance(boundaries, dict):
        raise ScanResultConsistencyError(
            "effective policy trust_boundaries must be a mapping"
        )
    for tool, boundary in boundaries.items():
        if not isinstance(tool, str):
            raise ScanResultConsistencyError(
                "effective policy trust_boundaries keys must be strings"
            )
        if not isinstance(boundary, TrustBoundary):
            raise ScanResultConsistencyError(
                f"effective policy trust boundary for {tool!r} must be a TrustBoundary"
            )
        if not isinstance(boundary.boundary, str) or not boundary.boundary.strip():
            raise ScanResultConsistencyError(
                f"effective policy trust boundary for {tool!r} requires a non-empty boundary"
            )
        if not isinstance(boundary.trust, str) or boundary.trust not in _TRUST_LEVELS:
            raise ScanResultConsistencyError(
                f"effective policy trust boundary for {tool!r} has invalid trust"
            )
        if not isinstance(boundary.note, str):
            raise ScanResultConsistencyError(
                f"effective policy trust boundary note for {tool!r} must be a string"
            )

    suppressions = policy.suppressions
    if not isinstance(suppressions, (list, tuple)):
        raise ScanResultConsistencyError(
            "effective policy suppressions must be a sequence of Suppression values"
        )
    if not all(isinstance(item, Suppression) for item in suppressions):
        raise ScanResultConsistencyError(
            "effective policy suppressions must contain Suppression values"
        )

    sources = policy.sources
    if not isinstance(sources, (list, tuple)) or not all(
        isinstance(source, str) for source in sources
    ):
        raise ScanResultConsistencyError(
            "effective policy sources must be a sequence of strings"
        )


def _validate_sealed_policy_time(result: ScanResult) -> None:
    policy = result.policy
    if not isinstance(policy, dict):
        raise ScanResultConsistencyError("sealed ScanResult policy must be a mapping")

    suppressions = policy.get("suppressions", [])
    if not isinstance(suppressions, list):
        raise ScanResultConsistencyError(
            "sealed ScanResult policy suppressions must be a list"
        )

    today = _utc_today()
    for index, suppression in enumerate(suppressions):
        if not isinstance(suppression, dict):
            raise ScanResultConsistencyError(
                f"sealed ScanResult policy suppression {index} must be a mapping"
            )
        expires = suppression.get("expires")
        if not isinstance(expires, str):
            raise ScanResultConsistencyError(
                f"sealed ScanResult policy suppression {index} requires an ISO expiry date"
            )
        try:
            expiry = date.fromisoformat(expires)
        except ValueError as exc:
            raise ScanResultConsistencyError(
                f"sealed ScanResult policy suppression {index} has invalid expiry date"
            ) from exc
        if expiry < today:
            raise ScanResultConsistencyError(
                "sealed ScanResult contains an expired policy suppression: "
                f"{expiry.isoformat()}"
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
                "input_schema": tool.input_schema,
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

    _validate_tool_schemas(result)

    expected_capabilities = reconcile_capability_scopes(infer_capabilities(result.tools))
    if result.capabilities != expected_capabilities:
        raise ScanResultConsistencyError(
            "capabilities do not match inference from discovered tool evidence"
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

    _validate_effective_policy(policy)
    expected_policy = policy_to_record(policy)
    if _canonical(result.policy) != _canonical(expected_policy):
        raise ScanResultConsistencyError(
            "policy record does not match the effective runtime policy"
        )

    current_fingerprint = getattr(result, "_semantic_fingerprint", None)
    if current_fingerprint is not None:
        assert_scan_result_consistent(result)
        return

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

    _validate_sealed_policy_time(result)
    _validate_result_projection(result)
    current_fingerprint = _semantic_fingerprint(result)
    if current_fingerprint != expected_fingerprint:
        raise ScanResultConsistencyError(
            "sealed ScanResult changed after scanner construction; refusing inconsistent output"
        )
