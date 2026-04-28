"""Passive HTTP collection utilities."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


@dataclass
class HTTPCollectionResult:
    """Container for passive HTTP response data."""

    final_url: str
    status_code: int
    headers: Dict[str, str]
    html_snippet: str


class HTTPCollector:
    """Fetches headers and lightweight HTML using a safe GET request."""

    def __init__(self, timeout: int = 10, user_agent: str | None = None) -> None:
        self.timeout = timeout
        self.user_agent = user_agent or "PassiveVulnIntelAgent/1.0"

    def collect(self, domain: str) -> HTTPCollectionResult:
        last_error: Exception | None = None
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            request = Request(url, headers={"User-Agent": self.user_agent})
            try:
                with urlopen(request, timeout=self.timeout) as response:
                    body = response.read(5000).decode("utf-8", errors="replace")
                    headers = {k: v for k, v in response.headers.items()}
                    return HTTPCollectionResult(
                        final_url=response.geturl(),
                        status_code=response.status,
                        headers=headers,
                        html_snippet=body,
                    )
            except HTTPError as exc:
                body = exc.read(5000).decode("utf-8", errors="replace")
                headers = {k: v for k, v in exc.headers.items()}
                return HTTPCollectionResult(
                    final_url=exc.geturl(),
                    status_code=exc.code,
                    headers=headers,
                    html_snippet=body,
                )
            except (URLError, TimeoutError, ValueError) as exc:
                last_error = exc

        raise RuntimeError(f"Unable to fetch HTTP(S) data for {domain}: {last_error}")
