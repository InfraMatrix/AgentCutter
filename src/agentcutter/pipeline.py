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


def load_system_prompt(path: Path | str = PROMPT_PATH) -> str:
    return Path(path).read_text(encoding="utf-8")


def run_timeline(capture: Path, binary: Path | str = BIN_PATH) -> dict:
    """Run `loupe-timeline --json capture` and return the parsed report."""
    proc = subprocess.run(
        [str(binary), "--json", str(capture)],
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


def build_report(
    capture: Path,
    out: Path | None = None,
    binary: Path | str = BIN_PATH,
    max_processes: int = 100,
    max_markers: int = 500,
) -> tuple[dict, Path]:
    """Full reduction step. Returns (report, report_path)."""
    capture = Path(capture)
    report = run_timeline(capture, binary)
    normalize_report_ids(report)
    add_syscalls_total(report)
    strip_series(report)
    trim_report(report, max_processes, max_markers)
    out = out or capture.parent / (capture.name.removesuffix(".jsonl") + ".report.json")
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report, out
