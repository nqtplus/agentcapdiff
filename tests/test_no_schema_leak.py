from agentcapdiff.models import ScanResult, ToolRecord


def test_tool_report_does_not_echo_raw_input_schema():
    result = ScanResult(
        tools=[ToolRecord("read_file", "Read file", "fixture", {"secretish": "do-not-echo"})]
    )
    payload = result.to_dict()
    assert "input_schema" not in payload["tools"][0]
    assert "do-not-echo" not in str(payload)
