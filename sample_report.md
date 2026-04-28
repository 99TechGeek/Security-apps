# Passive Vulnerability Intelligence Report: example.com

Generated: 2026-04-28T07:38:10.055452Z

## Summary
- HIGH: 0
- MEDIUM: 2
- LOW: 1

## Findings
### 1. Missing Header (MEDIUM)
- Description: Content-Security-Policy header is not present. Mitigates XSS and data injection attacks.
- Recommendation: Add the Content-Security-Policy HTTP response header with a secure policy.

### 2. Missing Header (MEDIUM)
- Description: Strict-Transport-Security header is not present. Forces HTTPS and prevents SSL stripping.
- Recommendation: Add the Strict-Transport-Security HTTP response header with a secure policy.

### 3. Missing Header (LOW)
- Description: X-Frame-Options header is not present. Reduces clickjacking risk.
- Recommendation: Add the X-Frame-Options HTTP response header with a secure policy.
