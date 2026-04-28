from analyzer.risk_analyzer import Finding
from reporter.json_reporter import JSONReporter
from reporter.markdown_reporter import MarkdownReporter


def test_json_report_summary_counts():
    reporter = JSONReporter()
    findings = [
        Finding(type="A", severity="HIGH", description="d", recommendation="r"),
        Finding(type="B", severity="LOW", description="d", recommendation="r"),
    ]
    report = reporter.build("example.com", findings)
    assert report["summary"]["high"] == 1
    assert report["summary"]["low"] == 1


def test_markdown_report_contains_findings():
    report = {
        "domain": "example.com",
        "summary": {"high": 1, "medium": 0, "low": 0},
        "findings": [
            {
                "type": "Missing Header",
                "severity": "MEDIUM",
                "description": "x",
                "recommendation": "y",
            }
        ],
    }
    output = MarkdownReporter().build(report)
    assert "Passive Vulnerability Intelligence Report" in output
    assert "Missing Header" in output
