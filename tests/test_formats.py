from agentcapdiff.formats import markdown_diff_report


def test_markdown_diff_report_shows_changes_and_risk():
    diff = {
        "base_risk_score": 10,
        "head_risk_score": 45,
        "risk_delta": 35,
        "capabilities_added": ["shell.execute"],
        "capabilities_removed": [],
        "tools_added": ["shell_execute"],
        "tools_removed": [],
        "head_findings": [
            {
                "severity": "MEDIUM",
                "message": "Capability requires human review: shell.execute",
            }
        ],
    }
    report = markdown_diff_report(diff)
    assert "10/100 → 45/100 (+35)" in report
    assert "shell.execute" in report
    assert "Policy findings in PR head" in report


def test_markdown_diff_report_escapes_untrusted_tool_names():
    diff = {
        "base_risk_score": 0,
        "head_risk_score": 0,
        "risk_delta": 0,
        "capabilities_added": [],
        "capabilities_removed": [],
        "tools_added": ["<script>[click](https://invalid)\n# heading"],
        "tools_removed": [],
        "head_findings": [],
    }
    report = markdown_diff_report(diff)
    assert "<script>" not in report
    assert "\\[click\\]\\(https://invalid\\)" in report
    assert "\n# heading" not in report


def test_markdown_diff_report_has_concise_no_change_state():
    report = markdown_diff_report(
        {
            "base_risk_score": 10,
            "head_risk_score": 10,
            "risk_delta": 0,
            "capabilities_added": [],
            "capabilities_removed": [],
            "tools_added": [],
            "tools_removed": [],
            "head_findings": [],
        }
    )
    assert "No capability or tool changes detected." in report
