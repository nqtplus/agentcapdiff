from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

from .jsonio import loads_unique
from .snapshot_semantics import validate_snapshot_semantics


class SnapshotArtifactError(ValueError):
    """Raised when a snapshot artifact is malformed, unsafe, or exceeds a safety bound."""


@dataclass(frozen=True)
class SnapshotLimits:
    max_file_bytes: int = 16_777_216
    max_depth: int = 64
    max_nodes: int = 200_000


DEFAULT_SNAPSHOT_LIMITS = SnapshotLimits()
_SEVERITIES = frozenset({"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"})
_CONFIDENCE = frozenset({"low", "medium", "high"})
_SCOPE_KINDS = frozenset({"restricted", "broad", "unknown"})
_UNKNOWN_SCOPE = frozenset({"deny", "review", "ignore"})
_TRUST_LEVELS = frozenset({"trusted", "untrusted", "unknown"})


def _fingerprint(capabilities: list[str]) -> str:
    canonical = {"schema": 1, "capabilities": sorted(set(capabilities))}
    encoded = json.dumps(
        canonical,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_structure(value: Any, source: Path, limits: SnapshotLimits) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0

    while stack:
        current, depth = stack.pop()
        if depth > limits.max_depth:
            raise SnapshotArtifactError(
                f"snapshot nesting exceeds depth limit {limits.max_depth}: {source}"
            )
        nodes += 1
        if nodes > limits.max_nodes:
            raise SnapshotArtifactError(
                f"snapshot structure exceeds node limit {limits.max_nodes}: {source}"
            )
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def _string_list(value: Any, field: str, source: Path) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise SnapshotArtifactError(f"snapshot field {field} must be a list of strings: {source}")
    return value


def _record_list(value: Any, field: str, source: Path) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise SnapshotArtifactError(f"snapshot field {field} must be a list of objects: {source}")
    return value


def _optional_string(
    record: dict[str, Any],
    key: str,
    source: Path,
    *,
    label: str | None = None,
) -> None:
    value = record.get(key)
    if value is not None and not isinstance(value, str):
        field = label or key
        raise SnapshotArtifactError(
            f"snapshot field {field} must be a string when present: {source}"
        )


def _validate_policy(policy: Any, source: Path) -> None:
    if policy is None:
        return
    if not isinstance(policy, dict):
        raise SnapshotArtifactError(f"snapshot policy must be an object or null: {source}")

    if "schema" in policy:
        schema = policy["schema"]
        if isinstance(schema, bool) or not isinstance(schema, int) or schema != 1:
            raise SnapshotArtifactError(f"unsupported snapshot policy schema; expected 1: {source}")

    for field in ("deny", "require_review", "sources"):
        if field in policy:
            _string_list(policy[field], f"policy.{field}", source)

    if "max_risk_score" in policy:
        value = policy["max_risk_score"]
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 100:
            raise SnapshotArtifactError(
                f"snapshot policy.max_risk_score must be an integer from 0 to 100: {source}"
            )

    if "unknown_scope" in policy:
        value = policy["unknown_scope"]
        if not isinstance(value, str) or value not in _UNKNOWN_SCOPE:
            raise SnapshotArtifactError(
                f"snapshot policy.unknown_scope must be deny, review, or ignore: {source}"
            )

    allow_by_tool = policy.get("allow_by_tool")
    if allow_by_tool is not None:
        if not isinstance(allow_by_tool, dict):
            raise SnapshotArtifactError(
                f"snapshot policy.allow_by_tool must be an object: {source}"
            )
        for tool, capabilities in allow_by_tool.items():
            _string_list(capabilities, f"policy.allow_by_tool.{tool}", source)

    scope_constraints = policy.get("scope_constraints")
    if scope_constraints is not None:
        if not isinstance(scope_constraints, dict):
            raise SnapshotArtifactError(
                f"snapshot policy.scope_constraints must be an object: {source}"
            )
        for capability, constraint in scope_constraints.items():
            if not isinstance(constraint, dict):
                raise SnapshotArtifactError(
                    "snapshot policy.scope_constraints entries must be objects: "
                    f"{source}"
                )
            if "allowed_kinds" in constraint:
                allowed_kinds = _string_list(
                    constraint["allowed_kinds"],
                    f"policy.scope_constraints.{capability}.allowed_kinds",
                    source,
                )
                if not set(allowed_kinds).issubset(_SCOPE_KINDS):
                    raise SnapshotArtifactError(
                        "snapshot policy scope constraint has invalid allowed_kinds: "
                        f"{source}"
                    )
            if "allowed_values" in constraint:
                _string_list(
                    constraint["allowed_values"],
                    f"policy.scope_constraints.{capability}.allowed_values",
                    source,
                )

    boundaries = policy.get("trust_boundaries")
    if boundaries is not None:
        if not isinstance(boundaries, dict):
            raise SnapshotArtifactError(
                f"snapshot policy.trust_boundaries must be an object: {source}"
            )
        for tool, annotation in boundaries.items():
            if not isinstance(annotation, dict):
                raise SnapshotArtifactError(
                    f"snapshot trust boundary for {tool} must be an object: {source}"
                )
            for field in ("boundary", "trust", "note"):
                _optional_string(
                    annotation,
                    field,
                    source,
                    label=f"policy.trust_boundaries.{tool}.{field}",
                )
            trust = annotation.get("trust")
            if trust is not None and trust not in _TRUST_LEVELS:
                raise SnapshotArtifactError(
                    f"snapshot trust boundary for {tool} has invalid trust: {source}"
                )

    suppressions = policy.get("suppressions")
    if suppressions is not None:
        items = _record_list(suppressions, "policy.suppressions", source)
        for item in items:
            for field in ("rule_id", "reason", "expires", "capability", "tool"):
                _optional_string(
                    item,
                    field,
                    source,
                    label=f"policy.suppressions.{field}",
                )
            expiry = item.get("expires")
            if isinstance(expiry, str):
                try:
                    date.fromisoformat(expiry)
                except ValueError as exc:
                    raise SnapshotArtifactError(
                        f"snapshot policy suppression has invalid expiry date: {source}"
                    ) from exc


def _validate_snapshot(snapshot: dict[str, Any], source: Path) -> None:
    if "schema" in snapshot:
        schema = snapshot["schema"]
        if isinstance(schema, bool) or not isinstance(schema, int) or schema != 1:
            raise SnapshotArtifactError(f"unsupported snapshot schema; expected 1: {source}")

    capability_schema = snapshot.get("capability_schema_version")
    if capability_schema is not None and capability_schema != "1":
        raise SnapshotArtifactError(
            f"unsupported capability schema version in snapshot; expected 1: {source}"
        )

    for field in ("capabilities", "tools"):
        if field in snapshot:
            _string_list(snapshot[field], field, source)

    risk_score = snapshot.get("risk_score")
    if risk_score is not None and (
        isinstance(risk_score, bool)
        or not isinstance(risk_score, int)
        or not 0 <= risk_score <= 100
    ):
        raise SnapshotArtifactError(
            f"snapshot risk_score must be an integer from 0 to 100: {source}"
        )

    severity = snapshot.get("max_severity")
    if severity is not None and (
        not isinstance(severity, str) or severity not in _SEVERITIES
    ):
        raise SnapshotArtifactError(f"snapshot max_severity is invalid: {source}")

    findings = snapshot.get("findings")
    if findings is not None:
        for item in _record_list(findings, "findings", source):
            for field in ("severity", "rule_id", "message", "capability", "tool"):
                _optional_string(item, field, source, label=f"findings.{field}")
            item_severity = item.get("severity")
            if item_severity is not None and item_severity not in _SEVERITIES:
                raise SnapshotArtifactError(f"snapshot finding severity is invalid: {source}")

    scopes = snapshot.get("scopes")
    if scopes is not None:
        for item in _record_list(scopes, "scopes", source):
            for field in ("capability", "tool", "kind", "reason"):
                _optional_string(item, field, source, label=f"scopes.{field}")
            kind = item.get("kind")
            if kind is not None and kind not in _SCOPE_KINDS:
                raise SnapshotArtifactError(f"snapshot scope kind is invalid: {source}")
            if "values" in item:
                _string_list(item["values"], "scopes.values", source)

    graph = snapshot.get("capability_graph")
    if graph is not None:
        if not isinstance(graph, dict):
            raise SnapshotArtifactError(
                f"snapshot capability_graph must be an object or null: {source}"
            )
        graph_schema = graph.get("schema_version")
        if graph_schema is not None and graph_schema != "1":
            raise SnapshotArtifactError(
                f"unsupported capability graph schema version; expected 1: {source}"
            )
        paths = graph.get("paths")
        if paths is not None:
            seen_path_ids: set[str] = set()
            for item in _record_list(paths, "capability_graph.paths", source):
                for field in ("id", "title", "severity", "confidence", "message"):
                    _optional_string(
                        item,
                        field,
                        source,
                        label=f"capability_graph.paths.{field}",
                    )
                path_id = item.get("id")
                if not isinstance(path_id, str) or not path_id.strip():
                    raise SnapshotArtifactError(
                        f"snapshot capability path id must be a non-empty string: {source}"
                    )
                if path_id in seen_path_ids:
                    raise SnapshotArtifactError(
                        "snapshot capability graph contains duplicate path id "
                        f"{path_id!r}: {source}"
                    )
                seen_path_ids.add(path_id)
                path_severity = item.get("severity")
                if path_severity is not None and path_severity not in _SEVERITIES:
                    raise SnapshotArtifactError(
                        f"snapshot capability path severity is invalid: {source}"
                    )
                confidence = item.get("confidence")
                if confidence is not None and confidence not in _CONFIDENCE:
                    raise SnapshotArtifactError(
                        f"snapshot capability path confidence is invalid: {source}"
                    )
                for field in ("capabilities", "tools", "evidence"):
                    if field in item:
                        _string_list(
                            item[field],
                            f"capability_graph.paths.{field}",
                            source,
                        )

    _validate_policy(snapshot.get("policy"), source)

    capabilities = snapshot.get("capabilities", [])
    stored_fingerprint = snapshot.get("capability_fingerprint")
    if stored_fingerprint is not None:
        if not isinstance(stored_fingerprint, str) or len(stored_fingerprint) != 64:
            raise SnapshotArtifactError(f"snapshot capability_fingerprint is invalid: {source}")
        try:
            int(stored_fingerprint, 16)
        except ValueError as exc:
            raise SnapshotArtifactError(
                f"snapshot capability_fingerprint is not hexadecimal: {source}"
            ) from exc
        expected = _fingerprint(capabilities)
        if stored_fingerprint != expected:
            raise SnapshotArtifactError(
                f"snapshot capability_fingerprint does not match capabilities: {source}"
            )

    try:
        validate_snapshot_semantics(snapshot)
    except ValueError as exc:
        raise SnapshotArtifactError(
            f"snapshot semantic inconsistency: {exc}: {source}"
        ) from exc


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON numeric constant is not allowed: {value}")


def load_snapshot(
    path: Path,
    limits: SnapshotLimits = DEFAULT_SNAPSHOT_LIMITS,
) -> dict[str, Any]:
    if path.is_symlink():
        raise SnapshotArtifactError(f"refusing symlinked snapshot artifact: {path}")
    if not path.exists():
        raise FileNotFoundError(path)
    if not path.is_file():
        raise SnapshotArtifactError(f"snapshot path must be a regular file: {path}")

    try:
        with path.open("rb") as handle:
            payload = handle.read(limits.max_file_bytes + 1)
    except OSError as exc:
        raise SnapshotArtifactError(f"snapshot artifact cannot be read safely: {path}") from exc

    if len(payload) > limits.max_file_bytes:
        raise SnapshotArtifactError(
            f"snapshot artifact exceeds {limits.max_file_bytes} byte limit: {path}"
        )

    try:
        text = payload.decode("utf-8")
    except UnicodeError as exc:
        raise SnapshotArtifactError(f"snapshot artifact is not valid UTF-8: {path}") from exc

    try:
        raw = loads_unique(text, parse_constant=_reject_json_constant)
    except (ValueError, RecursionError) as exc:
        raise SnapshotArtifactError(
            f"snapshot JSON is malformed or exceeds parser safety limits: {path}"
        ) from exc

    if not isinstance(raw, dict):
        raise SnapshotArtifactError(f"snapshot root must be a JSON object: {path}")

    _validate_structure(raw, path, limits)
    _validate_snapshot(raw, path)
    return raw
