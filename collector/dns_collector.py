"""Passive DNS collection utilities."""

from __future__ import annotations

import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class DNSCollectionResult:
    """Container for DNS lookup records."""

    records: Dict[str, List[str]]


class DNSCollector:
    """Collect A, MX, and TXT records using passive DNS resolution."""

    def collect(self, domain: str) -> DNSCollectionResult:
        records = {
            "A": self._resolve_a(domain),
            "MX": self._resolve_with_nslookup(domain, "MX"),
            "TXT": self._resolve_with_nslookup(domain, "TXT"),
        }
        return DNSCollectionResult(records=records)

    @staticmethod
    def _resolve_a(domain: str) -> list[str]:
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_INET)
            ips = sorted({info[4][0] for info in infos})
            return ips
        except socket.gaierror:
            return []

    @staticmethod
    def _resolve_with_nslookup(domain: str, record_type: str) -> list[str]:
        try:
            proc = subprocess.run(
                ["nslookup", "-type=" + record_type, domain],
                check=False,
                capture_output=True,
                text=True,
                timeout=8,
            )
            output = proc.stdout + "\n" + proc.stderr
            values: list[str] = []
            if record_type == "MX":
                for line in output.splitlines():
                    if "mail exchanger" in line:
                        values.append(line.split("=", 1)[-1].strip())
            elif record_type == "TXT":
                for line in output.splitlines():
                    match = re.search(r'text = "(.*)"', line)
                    if match:
                        values.append(match.group(1))
            return values
        except Exception:
            return []
