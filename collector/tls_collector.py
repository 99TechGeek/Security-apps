"""Passive TLS certificate inspection utilities."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict


@dataclass
class TLSCollectionResult:
    """Container for certificate details collected from TLS handshake."""

    certificate: Dict[str, Any]


class TLSCollector:
    """Retrieves public certificate metadata using a standard TLS handshake."""

    def __init__(self, timeout: float = 8.0) -> None:
        self.timeout = timeout

    def collect(self, domain: str) -> TLSCollectionResult:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()

        normalized = {
            "subject": cert.get("subject", ()),
            "issuer": cert.get("issuer", ()),
            "version": cert.get("version"),
            "serialNumber": cert.get("serialNumber"),
            "notBefore": cert.get("notBefore"),
            "notAfter": cert.get("notAfter"),
            "subjectAltName": cert.get("subjectAltName", ()),
            "expired": self._is_expired(cert.get("notAfter")),
        }
        return TLSCollectionResult(certificate=normalized)

    @staticmethod
    def _is_expired(not_after: str | None) -> bool | None:
        if not not_after:
            return None
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            return expiry < datetime.utcnow()
        except ValueError:
            return None
