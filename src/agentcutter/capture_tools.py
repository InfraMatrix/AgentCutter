"""Verification tools over the raw JSONL capture.

Each tool streams the capture line-by-line (never loads it whole) and
returns compact JSON with hard caps so nothing floods the model context.
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

MAX_EVENTS = 50
MAX_PROCS = 50
MAX_GROUPS = 20
MAX_FILES = 50
MAX_NET = 50


def _iter_events(capture: Path | str):
    with open(capture, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _sid_matches(event_sid, want) -> bool:
    """Compare session IDs as digit strings.

    Real captures use uint64 session IDs (up to 20 digits), past float64's
    exact-integer range, so callers may arrive with rounded or re-typed
    values. String comparison keeps exact matches working whether the ID
    arrived as int or string.
    """
    if event_sid is None or want is None:
        return False
    return str(event_sid) == str(want)


def _known_session_ids(capture: Path | str) -> list:
    seen: list = []
    for ev in _iter_events(capture):
        sid = ev.get("session_id")
        if sid is not None and sid not in seen:
            seen.append(sid)
    return seen


def _no_session(name: str, session_id) -> dict:
    return {
        "error": f"no events for session_id {session_id} in this capture",
        "hint": "copy the exact session_id digits from the report; "
        "the full list in this capture is in known_session_ids",
    }


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def get_session_events(
    capture: Path | str,
    session_id: int | str,
    type: str | None = None,  # noqa: A002 - tool schema name
    pid: int | None = None,
    limit: int = MAX_EVENTS,
) -> dict:
    """Raw events for one session, optionally filtered by type and/or pid."""
    limit = min(max(int(limit), 1), MAX_EVENTS)
    matched: list[dict] = []
    total = 0
    for ev in _iter_events(capture):
        if not _sid_matches(ev.get("session_id"), session_id):
            continue
        if type is not None and ev.get("type") != type:
            continue
        if pid is not None and ev.get("pid") != pid and ev.get("child_pid") != pid:
            continue
        total += 1
        if len(matched) < limit:
            matched.append(
                {k: v for k, v in ev.items() if k not in ("parent_session_id",)}
            )
    result = {
        "session_id": session_id,
        "total_matching": total,
        "returned": len(matched),
        "truncated": total > len(matched),
        "events": matched,
    }
    if total == 0:
        result.update(_no_session("get_session_events", session_id))
        result["known_session_ids"] = _known_session_ids(capture)
    return result


def get_process(capture: Path | str, pid: int) -> dict:
    """One process: argv/cwd/filename, children, exit resources, sessions seen in."""
    children: set[int] = set()
    info: dict = {"pid": pid, "seen": False}
    sessions: set[int] = set()
    for ev in _iter_events(capture):
        etype = ev.get("type")
        if etype == "fork" and ev.get("pid") == pid and ev.get("child_pid"):
            children.add(ev["child_pid"])
        if ev.get("pid") != pid:
            continue
        info["seen"] = True
        if ev.get("session_id") is not None:
            sessions.add(ev["session_id"])
        if etype == "exec":
            info.setdefault("argv", ev.get("argv"))
            info.setdefault("cwd", ev.get("cwd"))
            info.setdefault("filename", ev.get("filename"))
            info.setdefault("comm", ev.get("comm"))
        if etype in ("exit", "root_exit"):
            for k in ("exit_code", "cpu_user_ms", "cpu_sys_ms", "max_rss_kb"):
                if ev.get(k) is not None:
                    info[k] = ev[k]
    info["children"] = sorted(children)[:MAX_PROCS]
    info["children_truncated"] = len(children) > MAX_PROCS
    info["sessions"] = sorted(sessions)
    return info


def find_repeated_commands(capture: Path | str, session_id: int | str) -> dict:
    """Exec argv strings run more than once in a session, most frequent first."""
    counts: Counter[str] = Counter()
    for ev in _iter_events(capture):
        if (
            _sid_matches(ev.get("session_id"), session_id)
            and ev.get("type") == "exec"
            and ev.get("argv")
        ):
            counts[" ".join(ev["argv"])] += 1
    repeated = [
        {"command": cmd, "count": n} for cmd, n in counts.most_common(MAX_GROUPS) if n > 1
    ]
    result = {
        "session_id": session_id,
        "distinct_commands": len(counts),
        "repeated": repeated,
    }
    if len(counts) == 0:
        result.update(_no_session("find_repeated_commands", session_id))
        result["known_session_ids"] = _known_session_ids(capture)
    return result


def _capture_start(capture: Path | str) -> datetime | None:
    for ev in _iter_events(capture):
        ts = _parse_ts(ev.get("ts", ""))
        if ts:
            return ts
    return None


def files_opened(
    capture: Path | str,
    session_id: int | str,
    start_ms: int | None = None,
    end_ms: int | None = None,
    limit: int = MAX_FILES,
) -> dict:
    """File open/mutation events in a session, optional offset-ms window."""
    limit = min(max(int(limit), 1), MAX_FILES)
    start = _capture_start(capture)
    out: list[dict] = []
    total = 0
    for ev in _iter_events(capture):
        if not _sid_matches(ev.get("session_id"), session_id):
            continue
        if ev.get("type") not in (
            "file_open",
            "file_unlink",
            "file_rename",
            "file_chmod",
        ):
            continue
        ts = _parse_ts(ev.get("ts", ""))
        offset = int((ts - start).total_seconds() * 1000) if start and ts else None
        if start_ms is not None and (offset is None or offset < start_ms):
            continue
        if end_ms is not None and (offset is None or offset > end_ms):
            continue
        total += 1
        if len(out) < limit:
            item = {"type": ev["type"], "pid": ev.get("pid"), "offset_ms": offset}
            if ev.get("path"):
                item["path"] = ev["path"]
            if ev.get("old_path") or ev.get("new_path"):
                item["old_path"] = ev.get("old_path")
                item["new_path"] = ev.get("new_path")
            out.append(item)
    result = {
        "session_id": session_id,
        "total_matching": total,
        "returned": len(out),
        "truncated": total > len(out),
        "files": out,
    }
    if total == 0:
        result.update(_no_session("files_opened", session_id))
        result["known_session_ids"] = _known_session_ids(capture)
    return result


def network_activity(capture: Path | str, session_id: int | str) -> dict:
    """Net connects in a session, compact per-event plus per-destination counts."""
    events: list[dict] = []
    dests: Counter[str] = Counter()
    total = 0
    for ev in _iter_events(capture):
        if not _sid_matches(ev.get("session_id"), session_id) or ev.get("type") != "net_connect":
            continue
        total += 1
        dest = f"{ev.get('daddr')}:{ev.get('dport')}"
        dests[dest] += 1
        if len(events) < MAX_NET:
            events.append(
                {
                    "pid": ev.get("pid"),
                    "dest": dest,
                    "dns": bool(ev.get("dns")),
                    "ts": ev.get("ts"),
                }
            )
    result = {
        "session_id": session_id,
        "total_connects": total,
        "returned": len(events),
        "truncated": total > len(events),
        "by_destination": [
            {"dest": d, "count": c} for d, c in dests.most_common(MAX_NET)
        ],
        "events": events,
    }
    if total == 0:
        result.update(_no_session("network_activity", session_id))
        result["known_session_ids"] = _known_session_ids(capture)
    return result


# ---- Anthropic tool schemas + dispatcher ----

TOOL_SCHEMAS = [
    {
        "name": "get_session_events",
        "description": (
            "Return raw capture events for one session, optionally filtered "
            "by event type and/or pid. Use this to verify a claim from the "
            "report against the underlying events."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {"type": ["integer", "string"], "description": "Exact session_id digits from the report; pass through verbatim, do not round or reformat."},
                "type": {"type": "string"},
                "pid": {"type": "integer"},
                "limit": {"type": "integer", "default": MAX_EVENTS},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "get_process",
        "description": (
            "Look up one pid in the raw capture: argv, cwd, filename, child "
            "pids forked from it, and exit resources (cpu, rss)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"pid": {"type": "integer"}},
            "required": ["pid"],
        },
    },
    {
        "name": "find_repeated_commands",
        "description": (
            "List exec argv strings run more than once in a session, most "
            "frequent first. Evidence for re-run waste findings."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"session_id": {"type": "integer"}},
            "required": ["session_id"],
        },
    },
    {
        "name": "files_opened",
        "description": (
            "File open/mutation events in a session within an optional "
            "offset-ms window (offsets from capture start)."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {"type": ["integer", "string"], "description": "Exact session_id digits from the report; pass through verbatim, do not round or reformat."},
                "start_ms": {"type": "integer"},
                "end_ms": {"type": "integer"},
                "limit": {"type": "integer", "default": MAX_FILES},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "network_activity",
        "description": (
            "Network connects in a session: per-event detail plus "
            "per-destination counts."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"session_id": {"type": "integer"}},
            "required": ["session_id"],
        },
    },
]

_DISPATCH = {
    "get_session_events": get_session_events,
    "get_process": get_process,
    "find_repeated_commands": find_repeated_commands,
    "files_opened": files_opened,
    "network_activity": network_activity,
}


def call_tool(capture: Path | str, name: str, args: dict) -> str:
    """Run one tool call and return its compact JSON string result."""
    fn = _DISPATCH[name]
    result = fn(capture, **args)
    return json.dumps(result)[:20_000]
