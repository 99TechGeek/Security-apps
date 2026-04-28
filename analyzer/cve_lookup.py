"""Public CVE lookup module using NVD API."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlencode
from urllib.request import urlopen

from analyzer.tech_fingerprint import TechnologyDetection


@dataclass
class CVELookupConfig:
    cache_dir: str = ".cache"
    cache_ttl_seconds: int = 60 * 60 * 12
    timeout_seconds: int = 8


class CVELookup:
    NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, config: CVELookupConfig | None = None) -> None:
        self.config = config or CVELookupConfig()
        Path(self.config.cache_dir).mkdir(parents=True, exist_ok=True)

    def lookup(self, technologies: list[TechnologyDetection]) -> Dict[str, List[Dict[str, Any]]]:
        mapped: dict[str, list[dict[str, Any]]] = {}
        for tech in technologies:
            keyword = f"{tech.name} {tech.version}".strip() if tech.version else tech.name
            cache_key = self._cache_key(keyword)
            cached = self._load_cache(cache_key)
            if cached is not None:
                mapped[keyword] = cached
                continue

            cves = self._query_nvd(keyword)
            mapped[keyword] = cves
            self._write_cache(cache_key, cves)
        return mapped

    def _query_nvd(self, keyword: str) -> list[dict[str, Any]]:
        try:
            query = urlencode({"keywordSearch": keyword, "resultsPerPage": 3})
            url = f"{self.NVD_ENDPOINT}?{query}"
            with urlopen(url, timeout=self.config.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8", errors="replace"))

            vulnerabilities = payload.get("vulnerabilities", [])
            normalized: list[dict[str, Any]] = []
            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                metrics = cve.get("metrics", {})
                severity = self._extract_severity(metrics)
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break
                normalized.append({"id": cve.get("id"), "severity": severity, "summary": desc[:240]})
            return normalized
        except Exception:
            return []

    @staticmethod
    def _extract_severity(metrics: Dict[str, Any]) -> str:
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                base = entries[0].get("cvssData", {}).get("baseScore", 0)
                if base >= 9.0:
                    return "HIGH"
                if base >= 7.0:
                    return "MEDIUM"
                return "LOW"
        return "MEDIUM"

    def _cache_key(self, keyword: str) -> str:
        return hashlib.sha256(keyword.encode("utf-8")).hexdigest()

    def _cache_path(self, cache_key: str) -> Path:
        return Path(self.config.cache_dir) / f"{cache_key}.json"

    def _load_cache(self, cache_key: str) -> list[dict[str, Any]] | None:
        path = self._cache_path(cache_key)
        if not path.exists():
            return None
        if time.time() - path.stat().st_mtime > self.config.cache_ttl_seconds:
            return None
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            return None

    def _write_cache(self, cache_key: str, payload: list[dict[str, Any]]) -> None:
        path = self._cache_path(cache_key)
        path.write_text(json.dumps(payload, indent=2))
