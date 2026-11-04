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
    assert r["session_id"] == "300"
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
    assert "300" in r["known_session_ids"] and "400" in r["known_session_ids"]


def _big_id_capture(path):
    """Write a capture with a uint64 session_id past float64's exact range."""
    sid = 16896022792636465153  # > 2**53: JSON numbers lose precision here
    assert sid > 2**53 and int(float(sid)) != sid
    base = {"ts": "2026-01-01T00:00:00Z", "session_id": sid, "agent_name": "x"}
    _write_jsonl(path, [
        {**base, "type": "exec", "pid": 7, "argv": ["true"]},
        {**base, "type": "exec", "pid": 7, "argv": ["true"]},
        {**base, "type": "file_open", "pid": 7, "path": "/tmp/big.txt",
         "open_flags": 1},
        {**base, "type": "net_connect", "pid": 7,
         "daddr": "127.0.0.1", "dport": 53, "protocol": 17},
    ])
    return sid


def test_big_session_id_round_trip_all_tools(tmp_path):
    """IDs >2**53 survive a report write -> JSON parse -> tool lookup.

    Regression: the report used to carry session_id as a JSON number,
    so JS-float consumers (the model) saw a rounded value and every
    tool taking session_id matched nothing. String IDs pass through
    verbatim and match whether the caller passes int or string.
    """
    import json as _json

    cap = tmp_path / "big.jsonl"
    sid = _big_id_capture(cap)
    # string form survives a JSON round-trip exactly; float does not
    assert _json.loads(_json.dumps({"sid": str(sid)}))["sid"] == str(sid)
    for as_given in (sid, str(sid)):
        ev = t.get_session_events(cap, as_given)
        assert ev["total_matching"] == 4, as_given
        assert ev["session_id"] == str(sid)
        rep = t.find_repeated_commands(cap, as_given)
        assert rep["repeated"] == [{"command": "true", "count": 2}]
        assert rep["session_id"] == str(sid)
        f = t.files_opened(cap, as_given)
        assert f["total_matching"] == 1
        assert f["session_id"] == str(sid)
        n = t.network_activity(cap, as_given)
        assert n["total_connects"] == 1
        assert n["session_id"] == str(sid)
    # unknown-ID hint lists the exact digit string
    miss = t.get_session_events(cap, 999)
    assert str(sid) in miss["known_session_ids"]


def _write_jsonl(path, events):
    import json as _json

    with open(path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(_json.dumps(ev) + "\n")
    return path


def _io_capture(path):
    base = {"ts": "2026-01-01T00:00:00Z", "session_id": 700, "agent_name": "x"}
    return _write_jsonl(path, [
        {**base, "type": "file_open", "pid": 7, "path": "/tmp/f.txt", "open_flags": 1},
        {**base, "type": "file_read", "pid": 7, "path": "/tmp/f.txt",
         "bytes": 10, "duration_us": 5},
        {**base, "type": "file_write", "pid": 7, "path": "/tmp/f.txt",
         "bytes": 20, "duration_us": 0},
        {**base, "type": "file_close", "pid": 7, "path": "/tmp/f.txt",
         "read_bytes": 10, "write_bytes": 20, "duration_ms": 3},
    ])


def test_files_opened_includes_rw_and_close(tmp_path):
    cap = _io_capture(tmp_path / "io.jsonl")
    f = t.files_opened(cap, 700)
    assert f["total_matching"] == 4
    assert f["file_read_calls"] == 1
    assert f["file_write_calls"] == 1
    # byte totals come from file_close only (per-call bytes not double-counted)
    assert f["read_bytes"] == 10
    assert f["write_bytes"] == 20
    by_type = {e["type"]: e for e in f["files"]}
    assert by_type["file_read"]["bytes"] == 10
    assert by_type["file_read"]["duration_us"] == 5
    assert by_type["file_write"]["duration_us"] == 0
    assert by_type["file_close"]["read_bytes"] == 10
    assert by_type["file_close"]["write_bytes"] == 20


def _net_capture(path):
    base = {"ts": "2026-01-01T00:00:00Z", "session_id": 701, "agent_name": "x"}
    return _write_jsonl(path, [
        {**base, "type": "net_connect", "pid": 7,
         "daddr": "93.184.216.34", "dport": 443, "protocol": 6},
        {**base, "type": "net_send", "pid": 7,
         "daddr": "93.184.216.34", "dport": 443, "protocol": 6,
         "bytes": 100, "hostname": "example.com"},
        {**base, "type": "net_recv", "pid": 7,
         "daddr": "93.184.216.34", "dport": 443, "protocol": 6,
         "bytes": 50, "latency_us": 42, "hostname": "example.com"},
        {**base, "type": "net_recv", "pid": 7,
         "daddr": "93.184.216.34", "dport": 443, "protocol": 6,
         "bytes": 10, "latency_us": 0},
    ])


def test_network_activity_includes_sends_recvs(tmp_path):
    cap = _net_capture(tmp_path / "net.jsonl")
    n = t.network_activity(cap, 701)
    assert n["total_connects"] == 1
    assert n["sends"] == 1 and n["sent_bytes"] == 100
    assert n["recvs"] == 2 and n["recv_bytes"] == 60
    assert n["hostnames"] == ["example.com"]
    # first_response_us is the smallest nonzero pairing latency
    assert n["first_response_us"] == 42
    assert len(n["by_destination"]) == 1
    d = n["by_destination"][0]
    assert d["dest"] == "93.184.216.34:443"
    assert d["count"] == 1  # connects-only, unchanged semantics
    assert d["sends"] == 1 and d["recvs"] == 2
    assert d["hostnames"] == ["example.com"]
    assert sum(x["count"] for x in n["by_destination"]) == n["total_connects"]
