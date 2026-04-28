"""Markdown reporting for passive vulnerability intelligence."""

from __future__ import annotations

from datetime import datetime


class MarkdownReporter:
    """Renders a human-readable markdown report."""

    def build(self, json_report: dict) -> str:
        lines = [
            f"# Passive Vulnerability Intelligence Report: {json_report['domain']}",
            "",
            f"Generated: {datetime.utcnow().isoformat()}Z",
            "",
            "## Summary",
            f"- HIGH: {json_report['summary']['high']}",
            f"- MEDIUM: {json_report['summary']['medium']}",
            f"- LOW: {json_report['summary']['low']}",
            "",
            "## Findings",
        ]

        if not json_report["findings"]:
            lines.append("No significant passive findings detected.")
            return "\n".join(lines)

        for idx, finding in enumerate(json_report["findings"], start=1):
            lines.extend(
                [
                    f"### {idx}. {finding['type']} ({finding['severity']})",
                    f"- Description: {finding['description']}",
                    f"- Recommendation: {finding['recommendation']}",
                    "",
                ]
            )
        return "\n".join(lines)
