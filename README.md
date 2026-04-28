# Passive Vulnerability Intelligence Agent

A production-style, modular Python tool that passively analyzes a domain using public data only.

## Ethical & Safety Model
This project intentionally uses **passive** methods only:
- HTTP(S) response headers and HTML retrieval
- DNS lookups (A, MX, TXT)
- TLS certificate metadata inspection from standard handshake
- Public CVE enrichment using the NVD API

No active scanning, brute force, fuzzing, or exploitation is performed.

## Project Structure

```text
.
├── analyzer/
│   ├── cve_lookup.py
│   ├── risk_analyzer.py
│   └── tech_fingerprint.py
├── collector/
│   ├── dns_collector.py
│   ├── http_collector.py
│   └── tls_collector.py
├── reporter/
│   ├── json_reporter.py
│   └── markdown_reporter.py
├── tests/
│   ├── test_reporters.py
│   └── test_risk_analyzer.py
├── main.py
└── requirements.txt
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python main.py --domain example.com --json-out report.json --md-out report.md
```

## Output
The CLI prints JSON and writes:
- `report.json`: structured machine-readable report
- `report.md`: human-readable markdown report

The JSON contains:
- `domain`
- `summary` (`high`, `medium`, `low` counts)
- `findings` (typed findings with severity/reasoning/recommendations)
- `evidence` (headers, DNS, TLS, and detected technologies)

## Demo (Passive)

```bash
python main.py --domain example.com
```

Sample finding categories:
- Missing security headers (CSP, HSTS, X-Frame-Options)
- Potentially outdated technologies (header-based version checks)
- Public CVE matches (keyword-based lookup, cached)

## Testing

```bash
pytest -q
```
