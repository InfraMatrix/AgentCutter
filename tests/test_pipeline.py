"""Pipeline tests against AgentLoupe fixtures (no API)."""

import json

from agentcutter import pipeline
from conftest import BIN, all_fixtures, fixture


def test_report_strips_series(tmp_path):
    out = tmp_path / "report.json"
    report, _ = pipeline.build_report(fixture("timeline_multi_agent.jsonl"), out=out, binary=BIN)
    for s in report["sessions"]:
        assert "syscall_series" not in s
        assert "syscall_series_by_category" not in s
    # report.json on disk matches
    assert json.loads(out.read_text()) == report


def test_report_numbers_trace_to_reducer():
    raw = pipeline.run_timeline(fixture("timeline_basic.jsonl"), BIN)
    total = raw["total_events"]
    first_dur = raw["sessions"][0]["duration_ms"]
    stripped = pipeline.strip_series(raw)
    assert stripped["total_events"] == total
    assert [s["session_id"] for s in stripped["sessions"]] == [
        s["session_id"] for s in raw["sessions"]
    ]
    # spot-check a number survives stripping
    assert stripped["sessions"][0]["duration_ms"] == first_dur


def test_trim_keeps_top_by_duration(tmp_path):
    report, _ = pipeline.build_report(
        fixture("timeline_multi_agent.jsonl"),
        out=tmp_path / "r.json",
        binary=BIN,
        max_processes=1,
        max_markers=1,
    )
    for s in report["sessions"]:
        assert len(s["processes"]) <= 1
        assert len(s["markers"]) <= 1
    assert any("trimmed" in n for n in report.get("notes", []))


def test_all_fixtures_reduce(tmp_path):
    for fix in all_fixtures():
        report, _ = pipeline.build_report(
            fix, out=tmp_path / (fix.stem + ".report.json"), binary=BIN
        )
        assert report["sessions"], fix.name
