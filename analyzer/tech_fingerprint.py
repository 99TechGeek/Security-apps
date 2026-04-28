"""Technology fingerprinting based on passive artifacts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List


@dataclass
class TechnologyDetection:
    name: str
    version: str | None
    evidence: str


class TechnologyFingerprinter:
    """Extracts basic technologies from headers and page content."""

    SERVER_VERSION_RE = re.compile(r"([A-Za-z\-]+)/(\d+(?:\.\d+){0,3})")

    def detect(self, headers: Dict[str, str], html: str) -> List[TechnologyDetection]:
        detections: list[TechnologyDetection] = []

        server = headers.get("Server", "")
        powered_by = headers.get("X-Powered-By", "")

        for raw in (server, powered_by):
            if not raw:
                continue
            match = self.SERVER_VERSION_RE.search(raw)
            if match:
                detections.append(
                    TechnologyDetection(
                        name=match.group(1),
                        version=match.group(2),
                        evidence=f"header:{raw}",
                    )
                )
            else:
                detections.append(TechnologyDetection(name=raw, version=None, evidence=f"header:{raw}"))

        lowered = html.lower()
        if "wp-content" in lowered:
            detections.append(TechnologyDetection(name="WordPress", version=None, evidence="html:wp-content"))
        if "jquery" in lowered:
            detections.append(TechnologyDetection(name="jQuery", version=None, evidence="html:jquery"))

        unique: dict[tuple[str, str | None], TechnologyDetection] = {}
        for detection in detections:
            unique[(detection.name, detection.version)] = detection
        return list(unique.values())
