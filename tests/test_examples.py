"""Vendored live-kernel capture reduces cleanly (no API)."""

from pathlib import Path

import agentcutter
from agentcutter.pipeline import build_report

REPO = Path(agentcutter.__file__).resolve().parents[2]
BIN = REPO / "bin" / "forkline-timeline"


def test_live_capture_reduces(tmp_path):
    caps = sorted((REPO / "examples").glob("*-capture.jsonl"))
    assert caps, "no vendored capture in examples/"
    for cap in caps:
        report, _ = build_report(cap, out=tmp_path / "r.json", binary=BIN)
        assert report["sessions"], cap.name
        assert report["total_events"] > 0
        assert report["has_syscall_summary"], cap.name
