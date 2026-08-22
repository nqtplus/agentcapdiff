from agentcapdiff.models import Capability, ScanResult, ScopeEvidence


def test_scan_result_json_model_contains_scope_evidence():
    result = ScanResult(
        capabilities=[
            Capability(
                "filesystem.read",
                "read_file",
                10,
                "Can read local files.",
                scope=ScopeEvidence("restricted", ("./reports/**",), "static"),
            )
        ]
    )
    payload = result.to_dict()
    assert payload["capabilities"][0]["scope"]["kind"] == "restricted"
    assert payload["capabilities"][0]["scope"]["values"] == ("./reports/**",)
