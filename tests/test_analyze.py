"""Tests."""

from pathlib import Path

from browser_artifact_analyzer.core import analyze_artifacts

FIXTURES = Path(__file__).resolve().parent.parent / "sample_data"


class TestBrowserArtifactAnalyzer:
    def test_parses(self) -> None:
        r = analyze_artifacts(FIXTURES / "sample_browser_artifacts.json")
        assert len(r.capture.artifacts) >= 4

    def test_flags_suspicious(self) -> None:
        r = analyze_artifacts(FIXTURES / "sample_browser_artifacts.json")
        assert any(a.suspicious for a in r.capture.artifacts)

    def test_timeline_sorted(self) -> None:
        r = analyze_artifacts(FIXTURES / "sample_browser_artifacts.json")
        stamps = [a.timestamp for a in r.capture.artifacts if a.timestamp]
        assert stamps == sorted(stamps)
