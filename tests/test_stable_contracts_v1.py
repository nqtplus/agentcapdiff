import json

from agentcapdiff.formats import json_report, sarif_report
from agentcapdiff.models import (
    Capability,
    CapabilityEvidence,
    Finding,
    ScanResult,
    ScopeEvidence,
    ToolRecord,
    UNIVERSAL_CAPABILITY_SCHEMA_VERSION,
)


STABLE_JSON_SCAN_KEYS = {
    "risk_score",
    "max_severity",
    "tools",
    "capabilities",
    "capability_graph",
    "policy",
    "findings",
}


def _result() -> ScanResult:
    tool = ToolRecord(
        name="fetch_url",
        description="Fetch a URL",
        source="tools.json",
        adapter="mcp",
    )
    capability = Capability(
        id="network.external",
        tool="fetch_url",
        risk=15,
        reason="Can access external network resources.",
        source="tools.json",
        scope=ScopeEvidence(
            kind="restricted",
            values=("https://api.example.com/v1",),
            reason="Static schema limits the URL to an explicit value.",
        ),
        evidence=(
            CapabilityEvidence(
                adapter="mcp",
                source="tools.json",
                signal="name/description matched: fetch_url",
            ),
        ),
        confidence="medium",
    )
    finding = Finding(
        severity="HIGH",
        rule_id="capability.denied",
        message="Capability denied by policy: network.external",
        capability="network.external",
        tool="fetch_url",
        source="tools.json",
    )
    return ScanResult(
        tools=[tool],
        capabilities=[capability],
        findings=[finding],
        capability_graph={"schema_version": "1", "paths": []},
        policy={"deny": ["network.external"]},
    )


def test_universal_capability_schema_version_is_stable_for_v1():
    assert UNIVERSAL_CAPABILITY_SCHEMA_VERSION == "1"


def test_json_scan_top_level_contract_is_stable_and_additive():
    payload = json.loads(json_report(_result()))
    assert STABLE_JSON_SCAN_KEYS.issubset(payload)
    assert payload["tools"][0]["adapter"] == "mcp"
    assert payload["capabilities"][0]["schema_version"] == "1"
    assert payload["capabilities"][0]["scope"]["kind"] == "restricted"
    assert payload["findings"][0]["rule_id"] == "capability.denied"


def test_v1_json_contract_allows_safe_additive_top_level_fields():
    payload = json.loads(json_report(_result()))
    payload["future_additive_metadata"] = {"ignored_by_older_consumer": True}

    assert STABLE_JSON_SCAN_KEYS.issubset(payload)
    assert payload["future_additive_metadata"]["ignored_by_older_consumer"] is True


def test_sarif_contract_is_stable_and_source_anchored():
    payload = json.loads(sarif_report(_result()))
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "AgentCapDiff"
    result = payload["runs"][0]["results"][0]
    assert result["ruleId"] == "capability.denied"
    assert result["level"] == "error"
    assert result["message"]["text"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "tools.json"


def test_v1_contract_keeps_unknown_distinct_from_restricted():
    unknown = Capability(
        id="network.external",
        tool="fetch_url",
        risk=15,
        reason="Can access external network resources.",
        scope=ScopeEvidence(),
    )
    payload = unknown.scope
    assert payload.kind == "unknown"
    assert payload.values == ()
