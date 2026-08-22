from agentcapdiff.formats import markdown_diff_report


def test_markdown_diff_marks_proven_scope_expansion():
    change = {
        "capability": "filesystem.read",
        "tool": "read_file",
        "before": {"kind": "restricted", "values": ["./reports/**"]},
        "after": {"kind": "broad", "values": ["/**"]},
    }
    report = markdown_diff_report(
        {
            "base_risk_score": 10,
            "head_risk_score": 10,
            "risk_delta": 0,
            "capabilities_added": [],
            "capabilities_removed": [],
            "tools_added": [],
            "tools_removed": [],
            "scope_changes": [change],
            "scope_expansions": [change],
            "head_findings": [],
        }
    )
    assert "Scope changes" in report
    assert "EXPANSION" in report
    assert "reports" in report
