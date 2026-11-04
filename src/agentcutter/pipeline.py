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
    """Keep the top-N processes by duration_ms and a head+tail slice of markers.

    Markers keep the first and last halves of the cap so phase structure at
    both ends survives (startup imports at the head, network/exit at the
    tail); a middle-only window would hide one end of the session. Mutates
    and returns the report. Records what was dropped in notes so the model
    knows the counts are partial.
    """
    notes = report.setdefault("notes", [])
    for session in report.get("sessions", []):
        procs = session.get("processes", [])
        if len(procs) > max_processes:
            procs.sort(key=lambda p: p.get("duration_ms", 0), reverse=True)
            dropped = len(procs) - max_processes
            session["processes"] = procs[:max_processes]
            notes.append(
                f"session {session.get('session_id')}: processes trimmed "
                f"to top {max_processes} by duration_ms ({dropped} dropped)"
            )
        markers = session.get("markers", [])
        if len(markers) > max_markers:
            dropped = len(markers) - max_markers
            head = (max_markers + 1) // 2
            tail = max_markers - head
            session["markers"] = markers[:head] + markers[len(markers) - tail:]
            notes.append(
                f"session {session.get('session_id')}: markers trimmed "
                f"to first {head} + last {tail} of {len(markers)} "
                f"({dropped} dropped from the middle)"
            )
    return report


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
