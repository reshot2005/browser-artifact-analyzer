"""Core browser artifact analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from secintel_core import (
    Classification,
    Confidence,
    Evidence,
    Finding,
    InputArtifact,
    Provenance,
    Report,
    Severity,
    build_environment_info,
    canonical_config_hash,
    deterministic_finding_id,
    reproducible_now,
    sha256_file,
)
from secintel_core.security import safe_resolve_path

from browser_artifact_analyzer.parser import BrowserCapture, load_artifacts

TOOL_NAME = "browser-artifact-analyzer"
TOOL_VERSION = "0.1.0"


@dataclass
class AnalysisConfig:
    base_dir: Path = field(default_factory=lambda: Path.cwd())
    max_bytes: int = 50 * 1024 * 1024


@dataclass
class AnalysisResult:
    report: Report
    capture: BrowserCapture


def _resolve(base: Path, p: Path | str) -> Path:
    up = Path(p)
    return up.resolve() if up.is_absolute() else safe_resolve_path(base, p)


def analyze_artifacts(
    input_path: Path | str,
    *,
    config: AnalysisConfig | None = None,
    is_sample: bool = False,
) -> AnalysisResult:
    cfg = config or AnalysisConfig()
    resolved = _resolve(cfg.base_dir, input_path)
    if not resolved.is_file():
        raise ValueError(f"Artifact file not found: {resolved}")
    input_hash = sha256_file(resolved, max_bytes=cfg.max_bytes)
    started = reproducible_now()
    capture = load_artifacts(resolved)
    suspicious = [a for a in capture.artifacts if a.suspicious]
    findings: list[Finding] = [
        Finding(
            id=deterministic_finding_id("browser-observed", input_hash, {"n": len(capture.artifacts)}),
            title=f"Browser artifacts: {len(capture.artifacts)}",
            classification=Classification.OBSERVED,
            evidence=[Evidence(source=str(resolved), locator={"count": len(capture.artifacts)}, retrieved_at=started)],
            method="Browser history/cookie/download parsing",
            why_it_matters="Browser artifacts reconstruct user activity.",
            plain_language=f"Parsed {len(capture.artifacts)} browser artifacts.",
            severity=Severity.INFO,
            tags=["browser"],
            timestamp=started,
        )
    ]
    for art in suspicious:
        findings.append(
            Finding(
                id=deterministic_finding_id("browser-suspicious", input_hash, {"url": art.url, "ts": art.timestamp}),
                title=f"Suspicious browser artifact: {art.url}",
                classification=Classification.INFERRED,
                confidence=Confidence(score=0.82, rationale="URL/host matches suspicious pattern list", supporting_indicators=[art.url]),
                evidence=[Evidence(source=str(resolved), locator={"browser": art.browser, "type": art.artifact_type, "url": art.url}, retrieved_at=started)],
                method="Suspicious host/URL heuristic",
                why_it_matters="Malicious sites and paste hosts often appear in investigations.",
                plain_language=f"{art.browser} {art.artifact_type}: {art.url}",
                severity=Severity.HIGH,
                tags=["browser", "suspicious", art.artifact_type],
                timestamp=started,
            )
        )
    ended = reproducible_now()
    report = Report(
        provenance=Provenance(
            tool_name=TOOL_NAME,
            tool_version=TOOL_VERSION,
            config_hash=canonical_config_hash({}),
            inputs=[InputArtifact(path=str(resolved), sha256=input_hash, size_bytes=resolved.stat().st_size)],
            analysis_started_at=started,
            analysis_ended_at=ended,
            environment=build_environment_info(),
        ),
        findings=findings,
        is_sample_data=is_sample,
        metadata={"artifact_count": len(capture.artifacts), "suspicious_count": len(suspicious)},
    )
    return AnalysisResult(report=report, capture=capture)
