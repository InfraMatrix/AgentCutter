"""Pipeline tests against Forkline fixtures (no API)."""

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


def test_normalize_report_ids_stringifies_big_ids(tmp_path):
    big = 16896022792636465153
    assert big > 2**53
    report = {"sessions": [{"session_id": big, "processes": [], "markers": []}]}
    pipeline.normalize_report_ids(report)
    assert report["sessions"][0]["session_id"] == str(big)
    # JSON round-trip keeps the exact digits (numbers would not in JS floats)
    assert json.loads(json.dumps(report))["sessions"][0]["session_id"] == str(big)
    # idempotent
    pipeline.normalize_report_ids(report)
    assert report["sessions"][0]["session_id"] == str(big)


def test_add_syscalls_total_sums_distribution():
    report = {"sessions": [{
        "session_id": "1", "events": 273,
        "syscall_distribution": [
            {"name": "rt_sigaction", "count": 336},
            {"name": "openat", "count": 171},
        ],
    }]}
    pipeline.add_syscalls_total(report)
    assert report["sessions"][0]["syscalls_total"] == 507
    assert report["sessions"][0]["events"] == 273  # marker count untouched
    # idempotent, and never overwrites an annotated value
    pipeline.add_syscalls_total(report)
    assert report["sessions"][0]["syscalls_total"] == 507


def _report_with_markers(n):
    return {
        "notes": [],
        "sessions": [{
            "session_id": 1,
            "processes": [],
            "markers": [
                {"ts": f"t{i}", "offset_ms": i, "type": "file_open",
                 "pid": 1, "detail": f"/f{i}"}
                for i in range(n)
            ],
        }],
    }


def test_trim_markers_keeps_head_and_tail():
    report = pipeline.trim_report(_report_with_markers(10), max_markers=4)
    got = [m["detail"] for m in report["sessions"][0]["markers"]]
    assert got == ["/f0", "/f1", "/f8", "/f9"]
    assert any("dropped from the middle" in n for n in report["notes"])


def test_trim_markers_untouched_under_cap():
    report = pipeline.trim_report(_report_with_markers(3), max_markers=4)
    assert len(report["sessions"][0]["markers"]) == 3
    assert report["notes"] == []


def _big_session(sid, n_markers=600):
    markers = []
    for i in range(n_markers):
        mtype = "file_open"
        if i == n_markers // 2:
            mtype = "file_unlink"  # anomaly buried in the dropped middle
        markers.append({"ts": f"t{i}", "offset_ms": i, "type": mtype,
                        "pid": 1, "detail": f"/f{i}"})
    return {
        "session_id": sid,
        "processes": [{"duration_ms": i} for i in range(5)],
        "markers": markers,
        "top_programs_by_exec_count": [{"name": f"p{i}"} for i in range(30)],
        "syscall_distribution": [{"name": f"s{i}"} for i in range(150)],
        "syscall_categories": [{"name": f"c{i}"} for i in range(30)],
        "notable_syscalls": [{"name": f"n{i}"} for i in range(60)],
        "first_seen_syscalls": [{"name": f"f{i}"} for i in range(120)],
        "files_touched": [{"path": f"/x{i}", "count": 1} for i in range(250)],
        "network_destinations": [{"dest": f"10.0.0.1:{i}"} for i in range(120)],
        "program_syscall_attribution": [{"program": f"p{i}"} for i in range(60)],
    }


def test_trim_never_drops_section_or_session():
    report = {"notes": [], "sessions": [_big_session("a"), _big_session("b")]}
    pipeline.trim_report(report, max_processes=2, max_markers=100)
    # both sessions survive with every top-level section present
    assert len(report["sessions"]) == 2
    required = ["processes", "markers", "top_programs_by_exec_count",
                "syscall_distribution", "syscall_categories",
                "notable_syscalls", "first_seen_syscalls", "files_touched",
                "network_destinations", "program_syscall_attribution"]
    for s in report["sessions"]:
        for field in required:
            assert field in s, field
        assert "trimmed" in s  # machine-readable record of what was cut
        assert isinstance(s["trimmed"]["markers"]["dropped_middle"], int)
    # the mid-list unlink anomaly is rescued into the kept markers
    kept_types = [m["type"] for m in report["sessions"][0]["markers"]]
    assert "file_unlink" in kept_types
    assert len(report["sessions"][0]["markers"]) <= 100
