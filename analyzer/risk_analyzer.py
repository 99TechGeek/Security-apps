"""Risk analysis logic for passive vulnerability findings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from analyzer.tech_fingerprint import TechnologyDetection


@dataclass
class Finding:
    type: str
    severity: str
    description: str
    recommendation: str


class RiskAnalyzer:
    """Converts collected passive signals into prioritized findings."""

    REQUIRED_SECURITY_HEADERS = {
        "Content-Security-Policy": ("MEDIUM", "Mitigates XSS and data injection attacks."),
        "Strict-Transport-Security": ("MEDIUM", "Forces HTTPS and prevents SSL stripping."),
        "X-Frame-Options": ("LOW", "Reduces clickjacking risk."),
    }

    # Basic, opinionated age rules for demonstration purposes.
    VERSION_RISK_RULES = {
        "Apache": ("2.4.50", "HIGH", "Version may be affected by known path traversal issues."),
        "nginx": ("1.20.0", "MEDIUM", "Old nginx versions may miss recent security patches."),
        "PHP": ("8.1.0", "HIGH", "PHP branch may be unsupported or missing security updates."),
    }

    def analyze(
        self,
        http_headers: Dict[str, str],
        tls_data: Dict[str, Any],
        technologies: List[TechnologyDetection],
        cve_map: Dict[str, list[dict[str, Any]]],
    ) -> list[Finding]:
        findings: list[Finding] = []

        findings.extend(self._analyze_headers(http_headers))
        findings.extend(self._analyze_tls(tls_data))
        findings.extend(self._analyze_technology_risk(technologies))
        findings.extend(self._analyze_cves(cve_map))

        return findings

    def _analyze_headers(self, headers: Dict[str, str]) -> list[Finding]:
        findings: list[Finding] = []
        for header, (severity, reason) in self.REQUIRED_SECURITY_HEADERS.items():
            if header not in headers:
                findings.append(
                    Finding(
                        type="Missing Header",
                        severity=severity,
                        description=f"{header} header is not present. {reason}",
                        recommendation=f"Add the {header} HTTP response header with a secure policy.",
                    )
                )
        return findings

    def _analyze_tls(self, tls_data: Dict[str, Any]) -> list[Finding]:
        if tls_data.get("expired"):
            return [
                Finding(
                    type="TLS Certificate",
                    severity="HIGH",
                    description="TLS certificate appears expired.",
                    recommendation="Renew the certificate immediately and enable automated renewal.",
                )
            ]
        return []

    def _analyze_technology_risk(self, technologies: list[TechnologyDetection]) -> list[Finding]:
        findings: list[Finding] = []
        for tech in technologies:
            rule = self.VERSION_RISK_RULES.get(tech.name)
            if not rule or not tech.version:
                continue

            threshold, severity, reason = rule
            if self._version_lt(tech.version, threshold):
                findings.append(
                    Finding(
                        type="Outdated Technology",
                        severity=severity,
                        description=f"Detected {tech.name} {tech.version}, below {threshold}. {reason}",
                        recommendation=f"Upgrade {tech.name} to a supported and patched version.",
                    )
                )
        return findings

    def _analyze_cves(self, cve_map: Dict[str, list[dict[str, Any]]]) -> list[Finding]:
        findings: list[Finding] = []
        for tech_key, cves in cve_map.items():
            for cve in cves:
                severity = cve.get("severity", "MEDIUM")
                findings.append(
                    Finding(
                        type="Known CVE",
                        severity=severity,
                        description=f"{tech_key} may be affected by {cve.get('id')}: {cve.get('summary')}",
                        recommendation="Validate version exposure and apply vendor security patches.",
                    )
                )
        return findings

    @staticmethod
    def _version_lt(current: str, threshold: str) -> bool:
        def parse(v: str) -> list[int]:
            return [int(part) for part in v.split(".") if part.isdigit()]

        return parse(current) < parse(threshold)
