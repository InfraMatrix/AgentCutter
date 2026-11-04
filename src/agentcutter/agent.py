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
            f"duration {s.get('duration_ms')}ms, {s.get('events')} events, "
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


def run_analysis(
    report: dict,
    system_prompt: str,
    capture: Path | str,
    max_turns: int = MAX_TURNS,
) -> str:
    """Run the tool-use loop; return the final analysis text."""
    if max_turns < 1:
        raise ValueError("max_turns must be >= 1")
    client = get_client()
    messages: list[dict] = [{"role": "user", "content": build_first_message(report)}]
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
                # Final text was cut off: ask for continuation in the next turn.
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
    # Turn cap hit: return any text accumulated plus the last turn's text.
    tail = ""
    if resp is not None:
        tail = "".join(
            b.text for b in resp.content if getattr(b, "type", "") == "text"
        )
    if parts or tail:
        return "".join(parts) + tail
    return "[turn cap reached with no final text]"
