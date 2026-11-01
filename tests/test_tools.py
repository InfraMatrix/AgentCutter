"""Tool tests: caps, filters, and compact output (no API)."""

import json

from agentcutter import capture_tools as t
from conftest import fixture

MULTI = "timeline_multi_agent.jsonl"


def _session_ids():
    seen = []
    for ev in t._iter_events(fixture(MULTI)):
        if ev.get("session_id") not in seen:
            seen.append(ev["session_id"])
    return seen


def test_session_ids_known():
    assert _session_ids() == [300, 400]


def test_get_session_events_filter_and_cap():
    sid = 300
    all_ev = t.get_session_events(fixture(MULTI), sid, limit=50)
    assert all_ev["total_matching"] > 0
    execs = t.get_session_events(fixture(MULTI), sid, type="exec")
    assert execs["total_matching"] >= 1
    assert all(e["type"] == "exec" for e in execs["events"])
    capped = t.get_session_events(fixture(MULTI), sid, limit=1)
    assert capped["returned"] == 1
    assert capped["truncated"] == (capped["total_matching"] > 1)


def test_get_process_argv_children_resources():
    p = t.get_process(fixture(MULTI), 3000)
    assert p["seen"]
    assert p["argv"] == ["claude", "--project", "alpha"]
    assert 3001 in p["children"]
    p2 = t.get_process(fixture(MULTI), 999999)
    assert p2["seen"] is False


def test_find_repeated_commands_shape():
    r = t.find_repeated_commands(fixture(MULTI), 300)
    assert r["session_id"] == 300
    assert isinstance(r["repeated"], list)
    for item in r["repeated"]:
        assert item["count"] > 1


def test_files_opened_and_window():
    f = t.files_opened(fixture(MULTI), 300)
    assert f["total_matching"] >= 1
    assert any("alpha.txt" in (e.get("path") or "") for e in f["files"])
    narrow = t.files_opened(fixture(MULTI), 300, start_ms=10**9)
    assert narrow["total_matching"] == 0


def test_network_activity_counts():
    n = t.network_activity(fixture(MULTI), 300)
    assert n["total_connects"] >= 1
    assert sum(d["count"] for d in n["by_destination"]) == n["total_connects"]


def test_call_tool_compact_json():
    out = t.call_tool(fixture(MULTI), "get_process", {"pid": 4000})
    assert len(out) <= 20_000
    assert json.loads(out)["seen"] is True


def test_session_id_as_string_matches():
    sid = 300
    as_int = t.get_session_events(fixture(MULTI), sid)
    as_str = t.get_session_events(fixture(MULTI), str(sid))
    assert as_str["total_matching"] == as_int["total_matching"] > 0


def test_unknown_session_lists_known_ids():
    r = t.network_activity(fixture(MULTI), 12345)
    assert r["total_connects"] == 0
    assert "error" in r
    assert 300 in r["known_session_ids"] and 400 in r["known_session_ids"]
