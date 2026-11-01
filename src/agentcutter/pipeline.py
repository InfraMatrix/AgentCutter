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
    """Keep the top-N processes by duration_ms and first-N markers per session.

    Mutates and returns the report. Records what was dropped in notes so the
    model knows the counts are partial.
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
            session["markers"] = markers[:max_markers]
            notes.append(
                f"session {session.get('session_id')}: markers trimmed "
                f"to first {max_markers} ({dropped} dropped)"
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
    strip_series(report)
    trim_report(report, max_processes, max_markers)
    out = out or capture.parent / (capture.name.removesuffix(".jsonl") + ".report.json")
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report, out
