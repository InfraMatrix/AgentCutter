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
        if sid is None:
            continue
        sid = str(sid)
        if sid not in seen:
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
        "session_id": str(session_id),
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
        "session_id": str(session_id),
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


FILE_TYPES = (
    "file_open",
    "file_unlink",
    "file_rename",
    "file_chmod",
    "file_read",
    "file_write",
    "file_close",
)


def files_opened(
    capture: Path | str,
    session_id: int | str,
    start_ms: int | None = None,
    end_ms: int | None = None,
    limit: int = MAX_FILES,
) -> dict:
    """File open/mutation/read/write/close events in a session, optional offset-ms window.

    Offsets are capture offsets (ms since capture_start), matching the
    report's offset_ms/start_ms/end_ms. file_read/file_write items carry
    this call's bytes and duration_us (null = unknown: the entry probe
    missed or the call was sub-microsecond — never a dropped event).
    file_close items carry the open's cumulative read_bytes/write_bytes/
    duration_ms (0 here means the eBPF byte accounting saw no bytes;
    captures taken without io accounting report 0 — see demo.sh);
    byte totals below come from file_close only so nothing double-counts.
    """
    limit = min(max(int(limit), 1), MAX_FILES)
    start = _capture_start(capture)
    out: list[dict] = []
    total = 0
    read_calls = 0
    write_calls = 0
    read_bytes = 0
    write_bytes = 0
    for ev in _iter_events(capture):
        if not _sid_matches(ev.get("session_id"), session_id):
            continue
        if ev.get("type") not in FILE_TYPES:
            continue
        ts = _parse_ts(ev.get("ts", ""))
        offset = int((ts - start).total_seconds() * 1000) if start and ts else None
        if start_ms is not None and (offset is None or offset < start_ms):
            continue
        if end_ms is not None and (offset is None or offset > end_ms):
            continue
        total += 1
        etype = ev["type"]
        if etype == "file_read":
            read_calls += 1
        elif etype == "file_write":
            write_calls += 1
        elif etype == "file_close":
            if isinstance(ev.get("read_bytes"), int):
                read_bytes += ev["read_bytes"]
            if isinstance(ev.get("write_bytes"), int):
                write_bytes += ev["write_bytes"]
        if len(out) < limit:
            item = {"type": etype, "pid": ev.get("pid"), "offset_ms": offset}
            if ev.get("path"):
                item["path"] = ev["path"]
            if ev.get("open_flags") is not None and etype == "file_open":
                item["flags"] = ev["open_flags"]
            if ev.get("old_path") or ev.get("new_path"):
                item["old_path"] = ev.get("old_path")
                item["new_path"] = ev.get("new_path")
            if ev.get("mode") and etype == "file_chmod":
                item["mode"] = ev["mode"]
            if etype in ("file_read", "file_write"):
                item["bytes"] = ev.get("bytes", 0)
                # 0 means unknown (or sub-microsecond), not "instant":
                # surface as null so 0 keeps meaning measured-zero.
                dur = ev.get("duration_us")
                item["duration_us"] = dur if dur else None
            if etype == "file_close":
                item["read_bytes"] = ev.get("read_bytes", 0)
                item["write_bytes"] = ev.get("write_bytes", 0)
                item["duration_ms"] = ev.get("duration_ms", 0)
            out.append(item)
    result = {
        "session_id": str(session_id),
        "total_matching": total,
        "returned": len(out),
        "truncated": total > len(out),
        "file_read_calls": read_calls,
        "file_write_calls": write_calls,
        "read_bytes": read_bytes,
        "write_bytes": write_bytes,
        "files": out,
    }
    if total == 0:
        result.update(_no_session("files_opened", session_id))
        result["known_session_ids"] = _known_session_ids(capture)
    return result


def network_activity(capture: Path | str, session_id: int | str) -> dict:
    """Net connects/sends/recvs in a session, plus per-destination counts.

    by_destination[].count stays connects-only (sums to total_connects);
    send/recv volume sits beside it as sends/sent_bytes/recvs/recv_bytes.
    hostnames are DNS qnames / TLS SNIs parsed from send buffers (empty
    when the buffer holds no name); first_response_us is the smallest
    nonzero send->recv latency (time-to-first-byte, null when no send was
    ever paired with a recv — e.g. a UDP probe with no reply).
    Latency fields are null when unknown; 0 would mean a measured zero.
    """
    events: list[dict] = []
    transfers: list[dict] = []
    dests: dict[str, dict] = {}
    hostnames: set[str] = set()
    total = 0
    sends = 0
    sent_bytes = 0
    recvs = 0
    recv_bytes = 0
    first_response_us = None

    def dest_entry(dest: str) -> dict:
        entry = dests.get(dest)
        if entry is None:
            entry = {
                "dest": dest,
                "count": 0,
                "sends": 0,
                "sent_bytes": 0,
                "recvs": 0,
                "recv_bytes": 0,
                "hostnames": [],
            }
            dests[dest] = entry
        return entry

    for ev in _iter_events(capture):
        if not _sid_matches(ev.get("session_id"), session_id):
            continue
        etype = ev.get("type")
        if etype not in ("net_connect", "net_send", "net_recv"):
            continue
        dest = f"{ev.get('daddr')}:{ev.get('dport')}"
        entry = dest_entry(dest)
        if etype == "net_connect":
            total += 1
            entry["count"] += 1
            if len(events) < MAX_NET:
                events.append(
                    {
                        "pid": ev.get("pid"),
                        "dest": dest,
                        "dns": bool(ev.get("dns")),
                        "ts": ev.get("ts"),
                    }
                )
            continue
        lat = ev.get("latency_us") or None  # 0/absent = unpaired, not instant
        if etype == "net_send":
            sends += 1
            entry["sends"] += 1
            sent_bytes += ev.get("bytes", 0) or 0
            entry["sent_bytes"] += ev.get("bytes", 0) or 0
        else:  # net_recv
            recvs += 1
            entry["recvs"] += 1
            recv_bytes += ev.get("bytes", 0) or 0
            entry["recv_bytes"] += ev.get("bytes", 0) or 0
            if lat and (not first_response_us or lat < first_response_us):
                first_response_us = lat
        if ev.get("hostname"):
            hostnames.add(ev["hostname"])
            if ev["hostname"] not in entry["hostnames"]:
                entry["hostnames"].append(ev["hostname"])
        if len(transfers) < MAX_NET:
            transfers.append(
                {
                    "type": etype,
                    "pid": ev.get("pid"),
                    "dest": dest,
                    "bytes": ev.get("bytes", 0),
                    "latency_us": lat,
                    "hostname": ev.get("hostname", ""),
                    "ts": ev.get("ts"),
                }
            )
    by_dest = sorted(
        dests.values(), key=lambda d: (-(d["count"] + d["sends"] + d["recvs"]), d["dest"])
    )[:MAX_NET]
    result = {
        "session_id": str(session_id),
        "total_connects": total,
        "returned": len(events),
        "truncated": total > len(events),
        "sends": sends,
        "sent_bytes": sent_bytes,
        "recvs": recvs,
        "recv_bytes": recv_bytes,
        "hostnames": sorted(hostnames),
        "first_response_us": first_response_us,
        "by_destination": by_dest,
        "events": events,
        "transfers": transfers,
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
            "properties": {"session_id": {"type": ["integer", "string"], "description": "Exact session_id digits from the report; pass through verbatim, do not round or reformat."}},
            "required": ["session_id"],
        },
    },
    {
        "name": "files_opened",
        "description": (
            "File open/mutation/read/write/close events in a session within "
            "an optional offset-ms window (offsets from capture start, "
            "matching the report). Read/write items carry per-call bytes "
            "and duration_us; close items carry cumulative read/write "
            "bytes; totals come from closes only."
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
            "Network connects plus send/recv transfers in a session: "
            "per-event detail, per-destination counts (count stays "
            "connects-only; sends/recvs beside it), hostnames "
            "(DNS/TLS SNI), and first_response_us send->recv latency."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"session_id": {"type": ["integer", "string"], "description": "Exact session_id digits from the report; pass through verbatim, do not round or reformat."}},
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
