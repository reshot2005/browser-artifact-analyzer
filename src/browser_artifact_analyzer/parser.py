"""Browser history/cookie/download artifact analysis."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from secintel_core.security import bounded_read_file

_SUSPICIOUS_HOST = re.compile(r"(evil\.|pastebin|raw\.githubusercontent|malware|phishing)", re.I)


@dataclass(frozen=True)
class BrowserArtifact:
    browser: str
    artifact_type: str
    url: str
    title: str
    timestamp: str
    suspicious: bool


@dataclass
class BrowserCapture:
    artifacts: list[BrowserArtifact] = field(default_factory=list)


def load_artifacts(path: Path) -> BrowserCapture:
    data = json.loads(bounded_read_file(path, max_bytes=20 * 1024 * 1024))
    entries = data if isinstance(data, list) else data.get("artifacts", [])
    capture = BrowserCapture()
    for entry in entries:
        url = str(entry.get("url") or entry.get("host") or "")
        ts = str(entry.get("visit_time") or entry.get("start_time") or entry.get("expires") or "")
        capture.artifacts.append(
            BrowserArtifact(
                browser=str(entry.get("browser", "unknown")),
                artifact_type=str(entry.get("type", "history")),
                url=url,
                title=str(entry.get("title") or entry.get("name") or entry.get("path") or ""),
                timestamp=ts,
                suspicious=bool(_SUSPICIOUS_HOST.search(url)),
            )
        )
    capture.artifacts.sort(key=lambda a: a.timestamp)
    return capture
