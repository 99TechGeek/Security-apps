"""CLI entry point for Passive Vulnerability Intelligence Agent."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from analyzer.cve_lookup import CVELookup
from analyzer.risk_analyzer import RiskAnalyzer
from analyzer.tech_fingerprint import TechnologyFingerprinter
from collector.dns_collector import DNSCollector
from collector.http_collector import HTTPCollector
from collector.tls_collector import TLSCollector
from reporter.json_reporter import JSONReporter
from reporter.markdown_reporter import MarkdownReporter


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Passive Vulnerability Intelligence Agent")
    parser.add_argument("--domain", required=True, help="Target domain (e.g. example.com)")
    parser.add_argument("--json-out", default="report.json", help="Path to write JSON report")
    parser.add_argument("--md-out", default="report.md", help="Path to write Markdown report")
    return parser


def run(domain: str) -> dict:
    http_collector = HTTPCollector()
    dns_collector = DNSCollector()
    tls_collector = TLSCollector()
    fingerprinter = TechnologyFingerprinter()
    cve_lookup = CVELookup()
    analyzer = RiskAnalyzer()

    http_data = http_collector.collect(domain)

    dns_data = dns_collector.collect(domain)
    try:
        tls_data = tls_collector.collect(domain).certificate
    except Exception as exc:
        tls_data = {"error": str(exc), "expired": None}

    technologies = fingerprinter.detect(http_data.headers, http_data.html_snippet)
    cve_map = cve_lookup.lookup(technologies)

    findings = analyzer.analyze(http_data.headers, tls_data, technologies, cve_map)

    json_reporter = JSONReporter()
    report = json_reporter.build(domain=domain, findings=findings)

    report["evidence"] = {
        "http": {
            "final_url": http_data.final_url,
            "status_code": http_data.status_code,
            "headers": http_data.headers,
        },
        "dns": dns_data.records,
        "tls": tls_data,
        "technologies": [tech.__dict__ for tech in technologies],
    }
    return report


def main() -> None:
    args = build_parser().parse_args()
    report = run(args.domain)

    json_path = Path(args.json_out)
    md_path = Path(args.md_out)

    json_path.write_text(json.dumps(report, indent=2))
    md_report = MarkdownReporter().build(report)
    md_path.write_text(md_report)

    print(json.dumps(report, indent=2))
    print(f"\nMarkdown report written to {md_path}")


if __name__ == "__main__":
    main()
