"""Agent loop with the Anthropic SDK mocked + dry-run CLI (no API)."""

from types import SimpleNamespace

import agentcutter.agent as agent_mod
from agentcutter.cli import dry_run_analysis, main
from conftest import BIN, fixture


class _FakeMessages:
    """First call: one tool_use. Second call: final text. Records requests."""

    def __init__(self):
        self.calls = []
        self.n = 0

    def create(self, **kwargs):
        self.calls.append(kwargs)
        self.n += 1
        if self.n == 1:
            tu = SimpleNamespace(
                type="tool_use",
                id="tu_1",
                name="find_repeated_commands",
                input={"session_id": 300},
            )
            return SimpleNamespace(content=[tu])
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text="FINAL ANALYSIS")]
        )


def _install_fake(monkeypatch):
    fake = _FakeMessages()
    monkeypatch.setattr(
        agent_mod, "get_client", lambda: SimpleNamespace(messages=fake)
    )
    return fake


def test_loop_calls_tool_and_returns_text(monkeypatch):
    from agentcutter.pipeline import build_report
    import tempfile, pathlib

    with tempfile.TemporaryDirectory() as d:
        report, _ = build_report(
            fixture("timeline_basic.jsonl"),
            out=pathlib.Path(d) / "r.json",
            binary=BIN,
        )
    assert sorted(s["session_id"] for s in report["sessions"]) == ["100", "200"]
    fake = _install_fake(monkeypatch)
    text = agent_mod.run_analysis(
        report, "system prompt", fixture("timeline_basic.jsonl"), max_turns=5
    )
    # two sessions -> two per-session threads plus a summary-only comparison
    assert len(fake.calls) == 4
    assert "## Session 100" in text and "## Session 200" in text
    assert "## Cross-session comparison" in text
    assert "FINAL ANALYSIS" in text
    first = fake.calls[0]
    assert first["model"] == agent_mod.MODEL
    assert first["system"] == "system prompt"
    assert first["tools"]  # schemas passed
    # the per-session tool call carried the tool_result back
    contents = fake.calls[1]["messages"][-1]["content"]
    assert contents[0]["type"] == "tool_result"


def test_continuation_on_max_tokens(monkeypatch):
    """A text-only turn cut off by max_tokens is continued, then joined."""
    calls = {"n": 0}

    class Split:
        def create(self, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return SimpleNamespace(
                    content=[SimpleNamespace(type="text", text="PART1 ")],
                    stop_reason="max_tokens",
                )
            return SimpleNamespace(
                content=[SimpleNamespace(type="text", text="PART2")],
                stop_reason="end_turn",
            )

    monkeypatch.setattr(
        agent_mod, "get_client", lambda: SimpleNamespace(messages=Split())
    )
    text = agent_mod.run_analysis(
        {"sessions": []}, "sys", fixture("timeline_basic.jsonl"), max_turns=5
    )
    assert text == "PART1 PART2"
    assert calls["n"] == 2


def test_per_session_calls_keep_all_sections(monkeypatch):
    """3 large sessions -> 3 complete analyses + 1 summary-only comparison."""
    from agentcutter import pipeline

    def big_session(sid):
        return {
            "session_id": sid, "agent": "a", "duration_ms": 100,
            "events": 600, "marker_total": 600,
            "processes": [{"pid": 1, "duration_ms": 100}],
            "markers": [
                {"ts": "t", "offset_ms": i, "type": "file_open",
                 "pid": 1, "detail": f"/f{i}"} for i in range(600)
            ],
            "top_programs_by_exec_count": [], "top_programs_by_wall_time": [],
            "syscall_distribution": [{"name": "read"}],
            "syscall_categories": [{"name": "file"}],
            "notable_syscalls": [{"name": "execve"}],
            "first_seen_syscalls": [{"name": "read"}],
            "files_touched": [{"path": "/f", "count": 1}],
            "network_destinations": [{"dest": "127.0.0.1:53"}],
            "program_syscall_attribution": [],
        }

    report = {"notes": [], "sessions": [big_session("s1"), big_session("s2"),
                                       big_session("s3")]}
    pipeline.trim_report(report, max_markers=100)

    sent_messages = []

    class PerSession:
        def __init__(self):
            self.n = 0

        def create(self, **kwargs):
            self.n += 1
            sent_messages.append(kwargs["messages"])
            tag = f"ANALYSIS-{self.n}"
            return SimpleNamespace(
                content=[SimpleNamespace(type="text", text=tag)],
                stop_reason="end_turn",
            )

    fake = PerSession()
    monkeypatch.setattr(
        agent_mod, "get_client", lambda: SimpleNamespace(messages=fake)
    )
    text = agent_mod.run_analysis(
        report, "system prompt", fixture("timeline_basic.jsonl"), max_turns=3
    )
    # 3 per-session analyses plus one cross-session comparison call
    assert fake.n == 4
    for sid in ("s1", "s2", "s3"):
        assert f"## Session {sid}" in text
    assert "## Cross-session comparison" in text
    # each per-session message carries every top-level section + trimmed
    required = ["processes", "markers", "syscall_distribution",
                "syscall_categories", "notable_syscalls",
                "first_seen_syscalls", "files_touched",
                "network_destinations", "program_syscall_attribution",
                "trimmed"]
    for msgs in sent_messages[:3]:
        body = msgs[0]["content"]
        for field in required:
            assert field in body, field
    # the comparison call carries summaries only, never raw markers
    compare_body = sent_messages[3][0]["content"]
    assert "ANALYSIS-" in compare_body and "file_open" not in compare_body


def test_inventory_survives_truncation():
    report = {
        "sessions": [
            {"session_id": 1, "agent": "a", "duration_ms": 10,
             "events": 5, "processes": [1], "markers": [1, 2]},
            {"session_id": 2, "agent": "b", "duration_ms": 20,
             "events": 6, "processes": [1, 2], "markers": []},
        ]
    }
    msg = agent_mod.build_first_message(report, char_cap=50)
    assert "session 1 (a)" in msg and "session 2 (b)" in msg
    assert "truncated for context size" in msg


def test_inventory_notes_orphan_end():
    report = {
        "sessions": [
            {"session_id": 9, "agent": "a", "duration_ms": 10,
             "events": 5, "processes": [], "markers": [],
             "session_end_reason": "orphan_timeout",
             "orphan_gap_ms": 1200, "still_running": [42]},
        ]
    }
    msg = agent_mod.build_first_message(report, char_cap=5000)
    assert "orphan_timeout" in msg and "+1200ms" in msg and "42" in msg


def test_turn_cap(monkeypatch):
    class Endless:
        def create(self, **kwargs):
            tu = SimpleNamespace(
                type="tool_use", id="t", name="get_process", input={"pid": 3000}
            )
            return SimpleNamespace(content=[tu])

    monkeypatch.setattr(
        agent_mod, "get_client", lambda: SimpleNamespace(messages=Endless())
    )
    text = agent_mod.run_analysis(
        {"sessions": []}, "sys", fixture("timeline_basic.jsonl"), max_turns=3
    )
    assert "turn cap" in text


def test_dry_run_writes_no_api(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("META_MODEL_API_KEY", raising=False)
    cap = fixture("timeline_multi_agent.jsonl")
    rc = main(
        [
            "analyze", str(cap),
            "--dry-run",
            "--binary", str(BIN),
            "--report", str(tmp_path / "report.json"),
            "--output", str(tmp_path / "out.md"),
        ]
    )
    assert rc == 0
    text = (tmp_path / "out.md").read_text()
    assert "dry-run" in text.lower()
    assert "Session 300" in text


def test_dry_run_analysis_exercises_tools():
    from agentcutter.pipeline import build_report
    import tempfile, pathlib

    with tempfile.TemporaryDirectory() as d:
        report, _ = build_report(
            fixture("timeline_multi_agent.jsonl"),
            out=pathlib.Path(d) / "r.json",
            binary=BIN,
        )
    text = dry_run_analysis(report, fixture("timeline_multi_agent.jsonl"))
    assert "Session 300" in text and "Session 400" in text
