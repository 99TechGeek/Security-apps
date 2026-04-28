"""JSON reporting for passive vulnerability intelligence."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict
from typing import Any, Dict, List

from analyzer.risk_analyzer import Finding


class JSONReporter:
    """Builds JSON output contract from findings."""

    def build(self, domain: str, findings: list[Finding]) -> Dict[str, Any]:
        severities = Counter(f.severity for f in findings)
        return {
            "domain": domain,
            "summary": {
                "high": severities.get("HIGH", 0),
                "medium": severities.get("MEDIUM", 0),
                "low": severities.get("LOW", 0),
            },
            "findings": [asdict(f) for f in findings],
        }
