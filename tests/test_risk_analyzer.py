from analyzer.risk_analyzer import RiskAnalyzer
from analyzer.tech_fingerprint import TechnologyDetection


def test_missing_headers_detected():
    analyzer = RiskAnalyzer()
    findings = analyzer.analyze({}, {"expired": False}, [], {})
    types = [f.type for f in findings]
    assert types.count("Missing Header") == 3


def test_outdated_technology_detected():
    analyzer = RiskAnalyzer()
    tech = [TechnologyDetection(name="Apache", version="2.4.49", evidence="header")]
    findings = analyzer.analyze({}, {"expired": False}, tech, {})
    assert any(f.type == "Outdated Technology" for f in findings)
