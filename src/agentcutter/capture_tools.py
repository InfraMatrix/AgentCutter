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
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            # capture_meta is the loader's capture-level record (clock
            # anchor + probe set, session_id 0), not an agent event.
            if isinstance(ev, dict) and ev.get("type") == "capture_meta":
                continue
            yield ev


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


# ---- tool spans (from the reducer's tool_spans; see AgentLoupe README) ----

MAX_SPANS = 50
SPAN_SORTS = ("wall", "cpu", "read_bytes", "net")
_SPAN_CACHE: dict = {}


def _spans_report(capture: Path | str, spans: Path | str | None = None,
                  agent_process: str | None = None, binary: Path | str | None = None) -> dict:
    """The full (untrimmed) reducer report, cached per capture/spans file.

    Tool spans are computed by loupe-timeline (process tree + optional
    harness hook file), not re-derived here, so every number matches the
    report the model was given.
    """
    from agentcutter.pipeline import BIN_PATH, run_timeline  # avoid import cycle

    cap = Path(capture)
    key = (str(cap.resolve()), cap.stat().st_mtime_ns,
           str(spans) if spans else None,
           Path(spans).stat().st_mtime_ns if spans and Path(spans).exists() else None,
           agent_process, str(binary or BIN_PATH))
    rep = _SPAN_CACHE.get(key)
    if rep is None:
        rep = run_timeline(cap, binary or BIN_PATH, spans=spans, agent_process=agent_process)
        _SPAN_CACHE.clear()
        _SPAN_CACHE[key] = rep
    return rep


def _net_volume(res: dict) -> int | None:
    sent, recv = res.get("net_sent_bytes"), res.get("net_recv_bytes")
    if sent is None and recv is None:
        return None
    return (sent or 0) + (recv or 0)


def _cpu_ms(res: dict) -> int | None:
    u, s = res.get("cpu_user_ms"), res.get("cpu_sys_ms")
    if u is None and s is None:
        return None
    return (u or 0) + (s or 0)


def span_key(span: dict) -> str:
    """Identity for "same tool call repeated": tool + its main argument,
    else the process argv."""
    inp = span.get("input") or {}
    if span.get("tool_name"):
        arg = inp.get("command") or inp.get("file_path") or inp.get("pattern") \
            or inp.get("url") or inp.get("path") or ""
        return f"{span['tool_name']}: {' '.join(str(arg).split())}"
    return " ".join(span.get("argv") or []) or span.get("program") or "?"


def compact_span(span: dict) -> dict:
    """One-line view of a span for listings (full detail via get_span)."""
    res = span.get("resources") or {}
    out = {
        "span_id": span.get("span_id"),
        "source": span.get("source"),
        "attribution": span.get("attribution"),
        "tool_name": span.get("tool_name"),
        "what": span_key(span)[:200],
        "program": span.get("program"),
        "start_ms": span.get("start_ms"),
        "wall_ms": span.get("wall_ms"),
        "process_wall_ms": span.get("process_wall_ms"),
        "harness_duration_ms": span.get("harness_duration_ms"),
        "cpu_ms": _cpu_ms(res),
        "cpu_incomplete": res.get("cpu_incomplete", False),
        "max_rss_kb": res.get("max_rss_kb"),
        "processes": res.get("processes"),
        "file_opens": res.get("file_opens"),
        "file_reads": res.get("file_reads"),
        "read_bytes": res.get("read_bytes"),
        "write_bytes": res.get("write_bytes"),
        "files_mutated": res.get("files_mutated"),
        "net_connects": res.get("net_connects"),
        "net_sends": res.get("net_sends"),
        "net_recvs": res.get("net_recvs"),
        "net_bytes": _net_volume(res),
        "syscalls_total": res.get("syscalls_total"),
        "exit_code": span.get("exit_code"),
        "status": span.get("status"),
    }
    flags = []
    if span.get("role") == "hook":
        flags.append("hook_overhead")
    if span.get("outlived_span"):
        flags.append("outlived_span")
    if span.get("parallel_with"):
        flags.append(f"parallel_with:{len(span['parallel_with'])}")
    if span.get("open_ended"):
        flags.append("open_ended")
    out["flags"] = flags
    return {k: v for k, v in out.items() if v is not None and v != []}


def _sort_value(span: dict, sort_by: str):
    res = span.get("resources") or {}
    if sort_by == "cpu":
        return _cpu_ms(res)
    if sort_by == "read_bytes":
        return res.get("read_bytes")
    if sort_by == "net":
        vol = _net_volume(res)
        return vol if vol is not None else res.get("net_connects")
    return span.get("wall_ms")


def repeated_spans(spans: list[dict]) -> list[dict]:
    """Groups of identical spans (same tool + argv/command), count > 1,
    by total wall time: candidate waste. Hook spans are excluded."""
    groups: dict[str, dict] = {}
    for sp in spans:
        if sp.get("role") == "hook":
            continue
        key = span_key(sp)
        g = groups.setdefault(key, {"what": key[:200], "count": 0, "total_wall_ms": 0,
                                    "total_cpu_ms": None, "span_ids": []})
        g["count"] += 1
        g["total_wall_ms"] += sp.get("wall_ms") or 0
        cpu = _cpu_ms(sp.get("resources") or {})
        if cpu is not None:
            g["total_cpu_ms"] = (g["total_cpu_ms"] or 0) + cpu
        if len(g["span_ids"]) < 20:
            g["span_ids"].append(sp.get("span_id"))
    rep = [g for g in groups.values() if g["count"] > 1]
    rep.sort(key=lambda g: (-g["total_wall_ms"], -g["count"], g["what"]))
    return rep[:MAX_GROUPS]


def get_tool_spans(
    capture: Path | str,
    session_id: int | str,
    sort_by: str = "wall",
    limit: int = MAX_SPANS,
    include_hooks: bool = False,
    spans: Path | str | None = None,
    agent_process: str | None = None,
    binary: Path | str | None = None,
) -> dict:
    """Per-tool-call spans for one session, costliest first.

    sort_by: wall | cpu | read_bytes | net. Spans whose sort field is null
    (signal not collected, or not attributable: time-window spans have no
    CPU) sort last, never as zero. Hook-overhead spans are excluded unless
    include_hooks.
    """
    if sort_by not in SPAN_SORTS:
        return {"error": f"sort_by must be one of {list(SPAN_SORTS)}"}
    limit = min(max(int(limit), 1), MAX_SPANS)
    rep = _spans_report(capture, spans, agent_process, binary)
    for s in rep.get("sessions", []):
        if not _sid_matches(s.get("session_id"), session_id):
            continue
        all_spans = s.get("tool_spans") or []
        hooks = [sp for sp in all_spans if sp.get("role") == "hook"]
        pool = all_spans if include_hooks else [sp for sp in all_spans if sp.get("role") != "hook"]
        ranked = sorted(
            pool,
            key=lambda sp: (_sort_value(sp, sort_by) is None,
                            -(_sort_value(sp, sort_by) or 0), sp.get("start_ms") or 0),
        )
        hook_wall = sum(sp.get("wall_ms") or 0 for sp in hooks)
        hook_cpu = [_cpu_ms(sp.get("resources") or {}) for sp in hooks]
        return {
            "session_id": str(session_id),
            "sort_by": sort_by,
            "total_spans": len(pool),
            "returned": min(limit, len(ranked)),
            "truncated": len(ranked) > limit,
            "spans": [compact_span(sp) for sp in ranked[:limit]],
            "agent_self": compact_span(s.get("agent_self") or {}),
            "resource_totals": s.get("resource_totals"),
            "io_bytes_source": s.get("io_bytes_source"),
            "reconciliation": s.get("tool_span_reconciliation"),
            "agent_process": s.get("agent_process"),
            "repeated": repeated_spans(pool),
            "hook_overhead": {
                "spans": len(hooks),
                "total_wall_ms": hook_wall,
                "total_cpu_ms": sum(c for c in hook_cpu if c is not None) if any(c is not None for c in hook_cpu) else None,
            },
            "harness": rep.get("harness"),
        }
    result = _no_session("get_tool_spans", session_id)
    result["known_session_ids"] = [str(s.get("session_id")) for s in rep.get("sessions", [])]
    return result


def get_span(
    capture: Path | str,
    span_id: str,
    spans: Path | str | None = None,
    agent_process: str | None = None,
    binary: Path | str | None = None,
) -> dict:
    """Full detail for one span (or an agent_self-N bucket): resources,
    argv/command, tool input summary, top files and destinations, notes."""
    rep = _spans_report(capture, spans, agent_process, binary)
    known = []
    for s in rep.get("sessions", []):
        cands = list(s.get("tool_spans") or [])
        if s.get("agent_self"):
            cands.append(s["agent_self"])
        for sp in cands:
            known.append(sp.get("span_id"))
            if sp.get("span_id") == span_id:
                out = dict(sp)
                out["session_id"] = str(s.get("session_id"))
                out["io_bytes_source"] = s.get("io_bytes_source")
                return out
    return {
        "error": f"no span {span_id!r} in this capture",
        "hint": "use span_id values from get_tool_spans or the report's tool_spans",
        "known_span_ids_sample": known[:40],
    }


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
        "name": "get_tool_spans",
        "description": (
            "Per-tool-call spans for a session, costliest first. Each span is "
            "one tool call: a child-process subtree of the agent "
            "(source process_tree), merged with the harness hook record "
            "when present (harness+process_tree: tool_name + input), or a "
            "harness call with no child process whose resources are the "
            "agent's own events in that time window (attribution "
            "time_window: approximate, no CPU). Also returns agent_self "
            "(the agent process's own work), resource_totals, the "
            "reconciliation check, repeated identical spans (candidate "
            "waste), and hook overhead."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {"type": ["integer", "string"], "description": "Exact session_id digits from the report; pass through verbatim, do not round or reformat."},
                "sort_by": {"type": "string", "enum": list(SPAN_SORTS), "default": "wall"},
                "limit": {"type": "integer", "default": MAX_SPANS},
                "include_hooks": {"type": "boolean", "default": False},
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "get_span",
        "description": (
            "Full detail for one span_id (or agent_self-N): resources "
            "(null = not collected), argv/command, tool input summary, "
            "top files with byte counts, top network destinations with "
            "hostnames, parallel_with, notes."
        ),
        "input_schema": {
            "type": "object",
            "properties": {"span_id": {"type": "string"}},
            "required": ["span_id"],
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
    "get_tool_spans": get_tool_spans,
    "get_span": get_span,
}

_SPAN_TOOLS = frozenset({"get_tool_spans", "get_span"})


def call_tool(
    capture: Path | str,
    name: str,
    args: dict,
    spans: Path | str | None = None,
    agent_process: str | None = None,
    binary: Path | str | None = None,
) -> str:
    """Run one tool call and return its compact JSON string result.

    spans / agent_process are pipeline options (the harness spans file
    and --agent-process), passed to the span tools only; the model never
    supplies them.
    """
    fn = _DISPATCH[name]
    args = dict(args or {})
    if name in _SPAN_TOOLS:
        for k in ("spans", "agent_process", "binary"):
            args.pop(k, None)
        result = fn(capture, spans=spans, agent_process=agent_process, binary=binary, **args)
    else:
        result = fn(capture, **args)
    return json.dumps(result)[:20_000]
