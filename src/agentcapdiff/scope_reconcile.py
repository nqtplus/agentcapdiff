from __future__ import annotations

from dataclasses import replace

from .models import Capability, ScopeEvidence


def _is_scoped(capability: Capability) -> bool:
    return capability.id.startswith("filesystem.") or capability.id == "network.external"


def _merged_scope(capabilities: list[Capability]) -> ScopeEvidence:
    if len(capabilities) == 1:
        return capabilities[0].scope

    scopes = [capability.scope for capability in capabilities]
    broad_scopes = [scope for scope in scopes if scope.kind == "broad"]
    if broad_scopes:
        values = tuple(
            sorted({value for scope in broad_scopes for value in scope.values})
        )
        if not values:
            values = tuple(sorted({value for scope in scopes for value in scope.values}))
        return ScopeEvidence(
            "broad",
            values,
            (
                "Duplicate static capability records are reconciled conservatively: "
                "at least one record establishes broad scope."
            ),
        )

    if any(scope.kind == "unknown" for scope in scopes):
        return ScopeEvidence(
            "unknown",
            (),
            (
                "Duplicate static capability records do not establish one consistent "
                "finite scope; uncertainty is preserved."
            ),
        )

    values = tuple(sorted({value for scope in scopes for value in scope.values}))
    if not values:
        return ScopeEvidence(
            "unknown",
            (),
            (
                "Duplicate static capability records do not establish a non-empty "
                "finite scope; uncertainty is preserved."
            ),
        )

    return ScopeEvidence(
        "restricted",
        values,
        (
            "Duplicate static capability records are reconciled to the union of their "
            "finite restricted scopes."
        ),
    )


def reconcile_capability_scopes(capabilities: list[Capability]) -> list[Capability]:
    """Give duplicate capability/tool records one conservative shared scope.

    Provenance records remain separate. Only scope semantics are reconciled so policy,
    graph, snapshot production, and snapshot validation cannot disagree by source order.
    """

    groups: dict[tuple[str, str], list[Capability]] = {}
    for capability in capabilities:
        if _is_scoped(capability):
            groups.setdefault((capability.id, capability.tool), []).append(capability)

    merged = {key: _merged_scope(group) for key, group in groups.items()}
    return [
        replace(capability, scope=merged[(capability.id, capability.tool)])
        if _is_scoped(capability)
        else capability
        for capability in capabilities
    ]
