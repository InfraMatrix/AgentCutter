"""Step 1-3 of the pipeline: capture.jsonl -> loupe-timeline --json -> report.json.

Strips the large, low-value syscall_series fields and optionally trims
processes/markers so the report fits the model context. Every number kept
traces back to the reducer output verbatim; trimming only drops entries.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parents[2]
BIN_PATH = PKG_ROOT / "bin" / "loupe-timeline"
PROMPT_PATH = PKG_ROOT / "prompts" / "analyze.md"

SERIES_FIELDS = ("syscall_series", "syscall_series_by_category")

# Marker types that always survive middle-trimming (security/behavior
# relevant or network endpoints): phase ends plus these carry the analysis.
ANOMALY_MARKER_TYPES = frozenset({
    "file_unlink", "file_rename", "file_chmod",
    "net_connect", "net_send", "net_recv",
})

# Caps for long per-session lists besides processes/markers. Sections are
# never dropped wholesale; over-cap lists are truncated head-only with the
# dropped count recorded in session["trimmed"] and notes.
LIST_CAPS = {
    "top_programs_by_exec_count": 20,
    "top_programs_by_wall_time": 20,
    "syscall_distribution": 100,
    "syscall_categories": 20,
    "notable_syscalls": 50,
    "first_seen_syscalls": 100,
    "files_touched": 200,
    "network_destinations": 100,
    "program_syscall_attribution": 50,
}

# Tool spans sent to the model: the costliest by wall time and by CPU
# (union), kept in start order. The tools see every span.
MAX_TOOL_SPANS = 40
# Per-span detail lists trimmed in the model message (get_span has all).
SPAN_DETAIL_CAPS = {"top_files": 3, "top_destinations": 3, "pids": 10, "mutated_paths": 5}


def load_system_prompt(path: Path | str = PROMPT_PATH) -> str:
    return Path(path).read_text(encoding="utf-8")


def run_timeline(
    capture: Path,
    binary: Path | str = BIN_PATH,
    spans: Path | str | None = None,
    agent_process: str | None = None,
) -> dict:
    """Run `loupe-timeline --json capture` and return the parsed report.

    spans: harness hook file (default: the reducer auto-detects
    <capture>.spans.jsonl). agent_process: --agent-process override.
    """
    cmd = [str(binary), "--json"]
    if spans:
        cmd += ["--spans", str(spans)]
    if agent_process:
        cmd += ["--agent-process", agent_process]
    proc = subprocess.run(
        cmd + [str(capture)],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"loupe-timeline failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def normalize_report_ids(report: dict) -> dict:
    """Stringify 64-bit IDs so JSON keeps full precision.

    loupe-timeline emits session_id as a JSON number; IDs past 2**53
    lose precision in JS-float consumers (the model), which then passes
    a rounded value back to the tools and matches nothing. Python ints
    are exact, so convert here, right after json.loads, before the
    report is written to disk or sent to the model. Idempotent.
    """
    for session in report.get("sessions", []):
        sid = session.get("session_id")
        if sid is not None and not isinstance(sid, str):
            session["session_id"] = str(sid)
    return report


def add_syscalls_total(report: dict) -> dict:
    """Annotate each session with its explicit syscall denominator.

    `events` counts markers (exec/fork/exit/file/net markers); the
    syscall_distribution counts sum to a different, larger total. The
    reducer never emits that sum, so analyses divide by the wrong base.
    Additive only: `events` is untouched. Idempotent.
    """
    for session in report.get("sessions", []):
        if session.get("syscalls_total") is None:
            dist = session.get("syscall_distribution") or []
            session["syscalls_total"] = sum(
                c.get("count", 0) for c in dist if isinstance(c, dict)
            )
    return report


def strip_series(report: dict) -> dict:
    """Remove syscall_series fields (large, low value to the model)."""
    for session in report.get("sessions", []):
        for field in SERIES_FIELDS:
            session.pop(field, None)
    return report


def trim_report(
    report: dict,
    max_processes: int = 100,
    max_markers: int = 500,
) -> dict:
    """Trim per-session lists so each session fits a model call's budget.

    Priority order (never drop a top-level section or a whole session):
    1. downsample markers: keep head+tail of the full sequence PLUS any
       anomaly markers (unlink/rename/chmod/net_*) from the dropped middle,
       up to the cap, in chronological order;
    2. truncate other long lists head-only with explicit dropped counts.

    Records exactly what was cut in session["trimmed"] (machine-readable,
    sent to the model) and in notes (human-readable, kept for compat).
    Mutates and returns the report.
    """
    notes = report.setdefault("notes", [])
    for session in report.get("sessions", []):
        trimmed: dict = {}
        procs = session.get("processes", [])
        if len(procs) > max_processes:
            procs.sort(key=lambda p: p.get("duration_ms", 0), reverse=True)
            dropped = len(procs) - max_processes
            session["processes"] = procs[:max_processes]
            trimmed["processes"] = {
                "total": dropped + max_processes,
                "kept": max_processes,
                "dropped": dropped,
                "policy": f"top {max_processes} by duration_ms",
            }
            notes.append(
                f"session {session.get('session_id')}: processes trimmed "
                f"to top {max_processes} by duration_ms ({dropped} dropped)"
            )
        markers = session.get("markers", [])
        if len(markers) > max_markers:
            kept, drop_note = _trim_markers(markers, max_markers)
            dropped = len(markers) - len(kept)
            session["markers"] = kept
            trimmed["markers"] = {
                "total": len(markers),
                "kept": len(kept),
                "dropped_middle": dropped,
                "policy": drop_note,
            }
            notes.append(
                f"session {session.get('session_id')}: markers trimmed "
                f"to {len(kept)} of {len(markers)} "
                f"({dropped} dropped from the middle; {drop_note})"
            )
        for field, cap in LIST_CAPS.items():
            items = session.get(field)
            if isinstance(items, list) and len(items) > cap:
                dropped = len(items) - cap
                session[field] = items[:cap]
                trimmed[field] = {
                    "total": dropped + cap,
                    "kept": cap,
                    "dropped": dropped,
                    "policy": f"first {cap} entries (+{dropped} more)",
                }
                notes.append(
                    f"session {session.get('session_id')}: {field} trimmed "
                    f"to first {cap} (+{dropped} more)"
                )
        if trimmed:
            session["trimmed"] = trimmed
    return report


def _trim_markers(markers: list, cap: int) -> tuple[list, str]:
    """Head+tail downsample that rescues anomaly markers from the middle.

    Anomalies (unlink/rename/chmod/net_*) are kept first, wherever they
    sit; the remaining budget goes to the sequence ends so phase
    structure at startup and tail survives. Total never exceeds cap.
    """
    if cap <= 0:
        return [], "cap is 0"
    anomaly_idx = [
        i for i, m in enumerate(markers)
        if m.get("type", "") in ANOMALY_MARKER_TYPES
    ]
    if len(anomaly_idx) > cap:
        # Pathological: more anomalies than budget; head+tail of those.
        head = (cap + 1) // 2
        tail = cap - head
        kept_idx = set(anomaly_idx[:head]) | set(anomaly_idx[len(anomaly_idx) - tail:])
        note = (
            f"over-cap anomalies: kept first {head} + last {tail} "
            f"of {len(anomaly_idx)} anomaly markers"
        )
    else:
        kept_idx = set(anomaly_idx)
        budget = cap - len(kept_idx)
        head = (budget + 1) // 2
        tail = budget - head
        kept_idx |= set(range(head)) | set(
            range(len(markers) - tail, len(markers))
        )
        note = (
            f"first {head} + last {tail} plus {len(anomaly_idx)} anomaly "
            f"markers (unlink/rename/chmod/net_*) rescued from the middle"
        )
    kept = [m for i, m in enumerate(markers) if i in kept_idx]
    return kept, note


def _span_cpu(sp: dict) -> int:
    res = sp.get("resources") or {}
    return (res.get("cpu_user_ms") or 0) + (res.get("cpu_sys_ms") or 0)


def annotate_tool_spans(report: dict) -> dict:
    """Add deterministic span summaries the analysis prompt relies on.

    session["repeated_tool_spans"]: identical spans (same tool + argv or
    command) run more than once — candidate waste, computed here so the
    model does not have to count. session["hook_overhead"]: the
    AgentLoupe hook's own processes (excluded from rankings).
    Additive and idempotent; computed on the full span list before trim.
    """
    from agentcutter.capture_tools import repeated_spans

    for session in report.get("sessions", []):
        spans = session.get("tool_spans")
        if spans is None:
            continue
        if "repeated_tool_spans" not in session:
            session["repeated_tool_spans"] = repeated_spans(spans)
        if "hook_overhead" not in session:
            hooks = [sp for sp in spans if sp.get("role") == "hook"]
            session["hook_overhead"] = {
                "spans": len(hooks),
                "total_wall_ms": sum(sp.get("wall_ms") or 0 for sp in hooks),
                "total_cpu_ms": sum(_span_cpu(sp) for sp in hooks),
            }
    return report


def trim_tool_spans(report: dict, max_spans: int = MAX_TOOL_SPANS) -> dict:
    """Keep the costliest spans (top by wall_ms and top by CPU, union, hook
    spans dropped first) in start order; thin per-span detail lists.
    Records what was cut in session["trimmed"]["tool_spans"]."""
    notes = report.setdefault("notes", [])
    for session in report.get("sessions", []):
        spans = session.get("tool_spans")
        if not spans:
            continue
        for sp in spans + ([session["agent_self"]] if session.get("agent_self") else []):
            for field, cap in SPAN_DETAIL_CAPS.items():
                v = sp.get(field)
                if isinstance(v, list) and len(v) > cap:
                    sp[field] = v[:cap]
                    sp.setdefault("trimmed_detail", {})[field] = len(v)
        if len(spans) <= max_spans:
            continue
        work = [sp for sp in spans if sp.get("role") != "hook"]
        half = max_spans // 2
        by_wall = sorted(work, key=lambda sp: -(sp.get("wall_ms") or 0))[:half]
        by_cpu = sorted(work, key=lambda sp: -_span_cpu(sp))[:max_spans]
        keep = {id(sp) for sp in by_wall}
        for sp in by_cpu:
            if len(keep) >= max_spans:
                break
            keep.add(id(sp))
        kept = [sp for sp in spans if id(sp) in keep]
        dropped = len(spans) - len(kept)
        session["tool_spans"] = kept
        session.setdefault("trimmed", {})["tool_spans"] = {
            "total": len(spans),
            "kept": len(kept),
            "dropped": dropped,
            "policy": f"top {half} by wall_ms + top by cpu up to {max_spans}, hook spans dropped first; get_tool_spans lists all",
        }
        notes.append(
            f"session {session.get('session_id')}: tool_spans trimmed to {len(kept)} "
            f"of {len(spans)} (costliest by wall/cpu kept; use get_tool_spans for all)"
        )
    return report


def build_report(
    capture: Path,
    out: Path | None = None,
    binary: Path | str = BIN_PATH,
    max_processes: int = 100,
    max_markers: int = 500,
    spans: Path | str | None = None,
    agent_process: str | None = None,
    max_tool_spans: int = MAX_TOOL_SPANS,
) -> tuple[dict, Path]:
    """Full reduction step. Returns (report, report_path)."""
    capture = Path(capture)
    report = run_timeline(capture, binary, spans=spans, agent_process=agent_process)
    normalize_report_ids(report)
    add_syscalls_total(report)
    strip_series(report)
    annotate_tool_spans(report)
    trim_report(report, max_processes, max_markers)
    trim_tool_spans(report, max_tool_spans)
    out = out or capture.parent / (capture.name.removesuffix(".jsonl") + ".report.json")
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report, out
