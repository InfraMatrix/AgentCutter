"""Muse Spark analysis agent: fixed-turn tool-use loop over the capture tools.

Endpoint/auth/model per CLAUDE.md: Anthropic Messages API format at
https://api.meta.ai, Bearer $META_MODEL_API_KEY, model muse-spark-1.3.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from agentcutter.capture_tools import TOOL_SCHEMAS, call_tool

MODEL = "muse-spark-1.3"
BASE_URL = "https://api.meta.ai"
MAX_TURNS = 10
MAX_OUTPUT_TOKENS = 8192
REPORT_CHAR_CAP = 60_000
CONTINUE_PROMPT = "Continue exactly where you left off, with no repetition."


def get_client():
    """Build the Anthropic SDK client (imported lazily for test mocking)."""
    from anthropic import Anthropic

    api_key = os.environ.get("META_MODEL_API_KEY")
    if not api_key:
        raise RuntimeError("META_MODEL_API_KEY is not set")
    return Anthropic(base_url=BASE_URL, auth_token=api_key)


def _syscalls_total(session: dict) -> int:
    """Explicit syscall denominator: annotated, else summed from the table."""
    if session.get("syscalls_total") is not None:
        return session["syscalls_total"]
    return sum(
        c.get("count", 0)
        for c in (session.get("syscall_distribution") or [])
        if isinstance(c, dict)
    )


def session_inventory(report: dict) -> str:
    """One line per session so the model knows what exists even if the
    report JSON below is truncated for context size."""
    lines = []
    for s in report.get("sessions", []):
        tail = ""
        if s.get("session_end_reason"):
            tail = f", end {s['session_end_reason']}"
            if s.get("orphan_gap_ms"):
                tail += f" (+{s['orphan_gap_ms']}ms past root exit)"
            if s.get("still_running"):
                tail += f" still running: {s['still_running']}"
        lines.append(
            f"- session {s.get('session_id')} ({s.get('agent')}): "
            f"duration {s.get('duration_ms')}ms, {s.get('events')} marker "
            f"events, {_syscalls_total(s)} syscalls, "
            f"{len(s.get('processes', []))} processes, "
            f"{len(s.get('markers', []))} markers{tail}"
        )
    return "\n".join(lines)


def build_first_message(report: dict, char_cap: int = REPORT_CHAR_CAP) -> str:
    text = json.dumps(report, indent=2)
    truncated = len(text) > char_cap
    if truncated:
        text = text[:char_cap] + "\n... [truncated for context size]"
    return (
        "Here is the trimmed loupe-timeline report for this capture "
        "(syscall_series stripped; processes/markers may be trimmed, see notes). "
        "Analyze it per your system prompt. Every number you cite must come "
        "from this report or from the verification tools.\n\n"
        "Sessions in this capture (complete list — if a session's detail was "
        "truncated below, pull what you need with the tools):\n"
        + session_inventory(report)
        + "\n\n"
        + text
    )


def build_session_message(
    session: dict, report: dict, char_cap: int = REPORT_CHAR_CAP
) -> str:
    """One session's complete detail as a single model message.

    Never drops a top-level section or a whole session: trimming (done in
    pipeline.trim_report) only thins entries inside lists, and exactly what
    was cut travels in session["trimmed"] plus the shared notes below.
    """
    sid = session.get("session_id")
    relevant_notes = [
        n for n in report.get("notes", [])
        if str(sid) in str(n)
    ]
    envelope = {
        "capture_start": report.get("capture_start"),
        "capture_end": report.get("capture_end"),
        "has_syscall_summary": report.get("has_syscall_summary"),
        "session": session,
        "shared_notes": [n for n in report.get("notes", []) if n not in relevant_notes],
        "session_notes": relevant_notes,
    }
    text = json.dumps(envelope, indent=2)
    truncated = len(text) > char_cap
    if truncated:
        # Priority trim for the wire only (the stored report is untouched):
        # thin markers further head+tail, keeping anomalies, then cut the
        # next-longest lists. The trimmed record says exactly what went.
        import copy

        slim = copy.deepcopy(session)
        markers = slim.get("markers", [])
        over = len(text) - char_cap
        if len(markers) > 10 and over > 0:
            from agentcutter.pipeline import ANOMALY_MARKER_TYPES

            anomaly_idx = [
                i for i, m in enumerate(markers)
                if m.get("type") in ANOMALY_MARKER_TYPES
            ]
            keep_total = max(10, len(markers) - (over // 200) - 1)
            keep_total = min(keep_total, len(markers) - 1)
            if len(anomaly_idx) >= keep_total:
                head = (keep_total + 1) // 2
                tail = keep_total - head
                idx = set(anomaly_idx[:head]) | set(anomaly_idx[len(anomaly_idx) - tail:])
            else:
                budget = keep_total - len(anomaly_idx)
                head = (budget + 1) // 2
                tail = budget - head
                idx = set(anomaly_idx) | set(range(head)) | set(
                    range(len(markers) - tail, len(markers)))
            dropped = len(markers) - len(idx)
            slim["markers"] = [m for i, m in enumerate(markers) if i in idx]
            trim_rec = dict(slim.get("trimmed", {}))
            trim_rec["markers_wire"] = {
                "policy": f"per-message budget: first {head} + last {tail} + anomalies",
                "dropped_from_wire": dropped,
            }
            slim["trimmed"] = trim_rec
            envelope["session"] = slim
            text = json.dumps(envelope, indent=2)
        if len(text) > char_cap:
            text = text[:char_cap] + "\n... [truncated for context size]"
    return (
        "Analyze ONLY this one session from the loupe-timeline report "
        "(syscall_series stripped; lists may be trimmed — session[\"trimmed\"] "
        "and session_notes say exactly what was cut). Every number you cite "
        "must come from this message or from the verification tools "
        "(pass session_id through verbatim as a string).\n\n"
        + text
    )


def _run_tool_loop(client, system_prompt: str, messages: list, capture, max_turns: int) -> str:
    """Run the tool-use loop for one message thread; return its final text."""
    parts: list[str] = []
    resp = None
    for _ in range(max_turns):
        resp = client.messages.create(
            model=MODEL,
            max_tokens=MAX_OUTPUT_TOKENS,
            system=system_prompt,
            messages=messages,
            tools=TOOL_SCHEMAS,
        )
        tool_uses = [b for b in resp.content if b.type == "tool_use"]
        if not tool_uses:
            parts.append("".join(b.text for b in resp.content if b.type == "text"))
            if getattr(resp, "stop_reason", "end_turn") == "max_tokens":
                messages.append({"role": "assistant", "content": resp.content})
                messages.append({"role": "user", "content": CONTINUE_PROMPT})
                continue
            return "".join(parts)
        messages.append({"role": "assistant", "content": resp.content})
        results = []
        for tu in tool_uses:
            try:
                output = call_tool(capture, tu.name, tu.input or {})
            except Exception as exc:  # tools must never break the loop
                output = json.dumps({"error": str(exc)})
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": tu.id,
                    "content": output,
                }
            )
        messages.append({"role": "user", "content": results})
    tail = ""
    if resp is not None:
        tail = "".join(
            b.text for b in resp.content if getattr(b, "type", "") == "text"
        )
    if parts or tail:
        return "".join(parts) + tail
    return "[turn cap reached with no final text]"


def _session_summary_line(session: dict) -> str:
    return (
        f"- session {session.get('session_id')} ({session.get('agent')}): "
        f"duration {session.get('duration_ms')}ms, {session.get('events')} "
        f"marker events, {_syscalls_total(session)} syscalls, "
        f"{len(session.get('processes', []))} processes, "
        f"{len(session.get('markers', []))} markers "
        f"(of {session.get('marker_total')})"
    )


def run_analysis(
    report: dict,
    system_prompt: str,
    capture: Path | str,
    max_turns: int = MAX_TURNS,
) -> str:
    """Analyze each session in its own model call, then compare summaries.

    One message thread per session keeps a large capture from truncating
    whole sessions (or their later sections) out of a single context
    window. The final comparison call receives only the per-session
    analysis summaries, never the raw detail again.
    """
    if max_turns < 1:
        raise ValueError("max_turns must be >= 1")
    client = get_client()
    sessions = report.get("sessions", [])
    if not sessions:
        # No sessions: fall back to the legacy single message.
        messages: list[dict] = [{"role": "user", "content": build_first_message(report)}]
        return _run_tool_loop(client, system_prompt, messages, capture, max_turns)
    sections: list[str] = []
    summaries: list[str] = []
    for session in sessions:
        messages = [
            {"role": "user", "content": build_session_message(session, report)}
        ]
        text = _run_tool_loop(client, system_prompt, messages, capture, max_turns)
        sections.append(
            f"## Session {session.get('session_id')} "
            f"({session.get('agent')})\n\n{text}"
        )
        summaries.append(
            _session_summary_line(session) + f"\n{text[:2000]}"
        )
    if len(sessions) > 1:
        compare_messages: list[dict] = [
            {
                "role": "user",
                "content": (
                    "Per-session analyses of one capture (summaries only — "
                    "do not ask for more detail, compare what is here):\n\n"
                    + "\n\n".join(summaries)
                    + "\n\nWrite a short cross-session comparison: wall "
                    "time, CPU, processes, network, and whether they show "
                    "the same inefficiency patterns."
                ),
            }
        ]
        comparison = _run_tool_loop(
            client, system_prompt, compare_messages, capture, max_turns
        )
        sections.append("## Cross-session comparison\n\n" + comparison)
    return "\n\n".join(sections)
