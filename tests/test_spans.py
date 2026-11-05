"""Tool-span tools, pipeline annotation/trim, and prompt wiring (no API)."""

import json
from pathlib import Path
from types import SimpleNamespace

import agentcutter
import agentcutter.agent as agent_mod
from agentcutter import capture_tools as t
from agentcutter.pipeline import (
    annotate_tool_spans,
    build_report,
    load_system_prompt,
    trim_tool_spans,
)
from conftest import BIN

REPO = Path(agentcutter.__file__).resolve().parents[2]
LIVE = REPO / "examples" / "live-capture.jsonl"
S1 = "9033520343339237377"


def test_get_tool_spans_toy_demo():
    r = t.get_tool_spans(LIVE, S1, binary=BIN)
    assert r["total_spans"] == 4
    assert sorted(sp["what"] for sp in r["spans"]) == [
        "echo agentcutter-demo-run1", "echo agentcutter-demo-run1", "true", "true"]
    assert r["reconciliation"]["ok"] is True
    # Python startup + loopback probe live in agent_self, not dropped.
    assert r["agent_self"]["file_opens"] > 0
    assert r["agent_self"]["net_connects"] == 2
    tot = r["resource_totals"]
    assert tot["file_opens"] == r["agent_self"]["file_opens"] + sum(
        sp["file_opens"] for sp in r["spans"])
    # costliest first by wall
    walls = [sp["wall_ms"] for sp in r["spans"]]
    assert walls == sorted(walls, reverse=True)
    # repeated identical spans flagged as candidate waste
    whats = {g["what"]: g["count"] for g in r["repeated"]}
    assert whats == {"echo agentcutter-demo-run1": 2, "true": 2}
    # null-not-zero: this capture had no io accounting / rw events
    assert "read_bytes" not in r["spans"][0]
    assert r["io_bytes_source"] == "none"


def test_get_tool_spans_sort_and_errors():
    by_cpu = t.get_tool_spans(LIVE, S1, sort_by="cpu", binary=BIN)
    cpus = [sp.get("cpu_ms") for sp in by_cpu["spans"]]
    assert cpus == sorted(cpus, reverse=True)
    # read_bytes is null everywhere here: still returns all spans (nulls last)
    assert t.get_tool_spans(LIVE, S1, sort_by="read_bytes", binary=BIN)["total_spans"] == 4
    assert "error" in t.get_tool_spans(LIVE, S1, sort_by="tokens", binary=BIN)
    missing = t.get_tool_spans(LIVE, "123", binary=BIN)
    assert "error" in missing and S1 in missing["known_session_ids"]


def test_get_span_detail_and_unknown():
    first = t.get_tool_spans(LIVE, S1, binary=BIN)["spans"][0]
    d = t.get_span(LIVE, first["span_id"], binary=BIN)
    assert d["span_id"] == first["span_id"]
    assert d["session_id"] == S1
    assert d["top_files"] and "resources" in d
    self_d = t.get_span(LIVE, "agent_self-1", binary=BIN)
    assert self_d["source"] == "agent_self"
    bad = t.get_span(LIVE, "span-999", binary=BIN)
    assert "error" in bad and "span-1" in bad["known_span_ids_sample"]


def test_call_tool_span_opts_not_model_controlled():
    out = json.loads(t.call_tool(
        LIVE, "get_tool_spans",
        {"session_id": S1, "spans": "/etc/passwd", "binary": "/bin/false"},
        binary=BIN))
    assert out["total_spans"] == 4  # model-supplied spans/binary ignored
    names = {s["name"] for s in t.TOOL_SCHEMAS}
    assert {"get_tool_spans", "get_span"} <= names


def _harness_capture(tmp_path):
    """Agent + Bash call (shell child) + Read call (in-process), with
    capture_meta and hook records carrying CLOCK_MONOTONIC."""
    base_ns = 1_800_000_000_000_000_000
    wall_base = base_ns - 3_600_000_000_000
    lines = []

    def ts(ms):
        from datetime import datetime, timezone
        ns = base_ns + int(ms * 1e6)
        dt = datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{ns % 1_000_000_000:09d}Z"

    def ev(ms, typ, pid, ppid, **kw):
        lines.append(json.dumps({"ts": ts(ms), "type": typ, "session_id": 7, "agent_name": "cc",
                                 "pid": pid, "ppid": ppid, "comm": "x", **kw}))

    lines.append(json.dumps({"ts": ts(0), "type": "capture_meta", "session_id": 0,
                             "wall_base_unix_ns": wall_base, "probes": {"file_rw_events": True}}))
    ev(0, "session_start", 100, 1)
    ev(0, "exec", 100, 1, argv=["claude"])
    ev(100, "fork", 100, 1, child_pid=200)
    ev(100.1, "exec", 200, 100, argv=["/bin/bash", "-c", "eval 'pytest -q'"])
    ev(150, "file_read", 200, 100, path="/r/t.py", bytes=1000)
    ev(900, "exit", 200, 100, exit_code=1, cpu_user_ms=700, cpu_sys_ms=50, max_rss_kb=1)
    ev(2050, "file_open", 100, 1, path="/r/weighted.py", result=0)
    ev(2060, "file_read", 100, 1, path="/r/weighted.py", bytes=5000)
    ev(5000, "exit", 100, 1, exit_code=0, cpu_user_ms=1, cpu_sys_ms=1, max_rss_kb=1)
    cap = tmp_path / "run.jsonl"
    cap.write_text("\n".join(lines) + "\n")

    def rec(event, tool, tid, ms, inp=None):
        mono = base_ns + int(ms * 1e6) - wall_base
        return json.dumps({"event": event, "tool_name": tool, "tool_use_id": tid,
                           "ts_ns": base_ns + int(ms * 1e6) + 5_000_000_000,  # realtime 5s off
                           "mono_ns": mono, "pid": 9, "ancestors": [100], "input": inp or {}})
    spans = tmp_path / "run.spans.jsonl"  # auto-detected by the reducer
    spans.write_text("\n".join([
        rec("pre", "Bash", "tu1", 90, {"command": "pytest -q"}),
        rec("post", "Bash", "tu1", 950),
        rec("pre", "Read", "tu2", 2000, {"file_path": "/r/weighted.py"}),
        rec("post", "Read", "tu2", 2100),
        rec("pre", "Bash", "tu3", 3000, {"command": "pytest -q"}),
        rec("post", "Bash", "tu3", 3100),
    ]) + "\n")
    return cap


def test_harness_spans_named_and_merged(tmp_path):
    cap = _harness_capture(tmp_path)
    r = t.get_tool_spans(cap, 7, binary=BIN)
    assert r["harness"]["clock"]["method"] == "monotonic"
    by_tool = {(sp.get("tool_name"), sp["source"]): sp for sp in r["spans"]}
    bash = by_tool[("Bash", "harness+process_tree")]
    assert bash["what"] == "Bash: pytest -q"
    assert bash["cpu_ms"] == 750 and bash["read_bytes"] == 1000 and bash["exit_code"] == 1
    read = by_tool[("Read", "harness")]
    assert read["attribution"] == "time_window"
    assert read["file_opens"] == 1 and read["read_bytes"] == 5000
    assert "cpu_ms" not in read  # null: cannot be split by window
    assert r["spans"][0]["what"] == "Bash: pytest -q"  # longest first
    assert r["reconciliation"]["ok"]
    # Two Bash calls with the same command: candidate waste.
    assert any(g["what"] == "Bash: pytest -q" and g["count"] == 2 for g in r["repeated"])


def test_build_report_annotates_and_trims(tmp_path):
    cap = _harness_capture(tmp_path)
    report, _ = build_report(cap, out=tmp_path / "r.json", binary=BIN)
    s = report["sessions"][0]
    assert s["tool_spans"] and s["agent_self"]
    assert s["repeated_tool_spans"][0]["count"] == 2
    assert s["hook_overhead"]["spans"] == 0
    # trimming keeps the costliest and records the cut
    rep = {"sessions": [{"session_id": "1", "tool_spans": [
        {"span_id": f"span-{i}", "wall_ms": i, "start_ms": i,
         "resources": {"cpu_user_ms": 100 - i, "cpu_sys_ms": 0},
         "top_files": [{"path": str(k)} for k in range(9)]} for i in range(100)]}]}
    annotate_tool_spans(rep)
    trim_tool_spans(rep, max_spans=10)
    kept = rep["sessions"][0]["tool_spans"]
    ids = {sp["span_id"] for sp in kept}
    assert len(kept) == 10 and "span-99" in ids and "span-0" in ids  # top wall + top cpu
    assert [sp["start_ms"] for sp in kept] == sorted(sp["start_ms"] for sp in kept)
    assert rep["sessions"][0]["trimmed"]["tool_spans"]["dropped"] == 90
    assert len(kept[0]["top_files"]) == 3 and kept[0]["trimmed_detail"]["top_files"] == 9


def test_capture_meta_not_an_event(tmp_path):
    cap = _harness_capture(tmp_path)
    assert all(ev["type"] != "capture_meta" for ev in t._iter_events(cap))
    assert "0" not in t._known_session_ids(cap)


def test_prompt_ranks_tool_calls_and_flags_repeats():
    p = load_system_prompt()
    assert "Where the time went" in p and "tool calls" in p
    assert "repeated_tool_spans" in p and "candidate waste" in p
    assert "time_window" in p and "null" in p
    assert "get_tool_spans" in p and "get_span" in p


def test_agent_loop_forwards_span_opts(monkeypatch, tmp_path):
    cap = _harness_capture(tmp_path)
    report, _ = build_report(cap, out=tmp_path / "r.json", binary=BIN)

    class Fake:
        def __init__(self):
            self.calls = []

        def create(self, **kw):
            self.calls.append(kw)
            if len(self.calls) == 1:
                return SimpleNamespace(content=[SimpleNamespace(
                    type="tool_use", id="tu", name="get_tool_spans",
                    input={"session_id": "7", "sort_by": "cpu"})])
            return SimpleNamespace(content=[SimpleNamespace(type="text", text="DONE")])

    fake = Fake()
    monkeypatch.setattr(agent_mod, "get_client", lambda: SimpleNamespace(messages=fake))
    text = agent_mod.run_analysis(report, "sys", cap, max_turns=3, tool_opts={"binary": BIN})
    assert "DONE" in text
    result = json.loads(fake.calls[1]["messages"][-1]["content"][0]["content"])
    assert result["sort_by"] == "cpu" and result["spans"][0]["tool_name"] == "Bash"
