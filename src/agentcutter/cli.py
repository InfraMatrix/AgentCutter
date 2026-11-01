"""`agentcutter analyze capture.jsonl [--dry-run]`: full pipeline to markdown."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agentcutter import capture_tools
from agentcutter.pipeline import BIN_PATH, PROMPT_PATH, build_report, load_system_prompt


def default_output(capture: Path) -> Path:
    name = capture.name
    if name.endswith(".jsonl"):
        name = name[: -len(".jsonl")]
    return capture.parent / f"{name}.analysis.md"


def dry_run_analysis(report: dict, capture: Path) -> str:
    """Deterministic no-API analysis: exercises pipeline + every tool."""
    lines = ["# AgentCutter dry-run analysis", ""]
    lines.append(f"Capture: `{capture}` (no API call made)")
    lines.append("")
    for s in report.get("sessions", []):
        sid = s.get("session_id")
        lines.append(
            f"## Session {sid} ({s.get('agent')}, "
            f"duration {s.get('duration_ms')}ms, {s.get('events')} events)"
        )
        top = (s.get("top_programs_by_wall_time") or [])[:3]
        for p in top:
            lines.append(f"- {p['name']}: exec={p['exec_count']} total={p['total_ms']}ms")
        rep = capture_tools.find_repeated_commands(capture, sid)
        if rep["repeated"]:
            lines.append("- repeated commands:")
            for r in rep["repeated"]:
                lines.append(f"  - `{r['command']}` x{r['count']}")
        net = capture_tools.network_activity(capture, sid)
        lines.append(f"- network connects: {net['total_connects']}")
        files = capture_tools.files_opened(capture, sid)
        lines.append(f"- file events: {files['total_matching']}")
        ev = capture_tools.get_session_events(capture, sid, limit=3)
        lines.append(f"- sample events verified: {ev['returned']}/{ev['total_matching']}")
        lines.append("")
    lines.append("_Dry run: run without --dry-run for the full Muse Spark analysis._")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentcutter")
    sub = parser.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="Analyze a capture into markdown.")
    a.add_argument("capture", type=Path, help="Raw AgentLoupe JSONL capture.")
    a.add_argument("--output", type=Path, default=None)
    a.add_argument("--report", type=Path, default=None,
                   help="Where to write report.json (default: next to capture).")
    a.add_argument("--binary", type=Path, default=BIN_PATH)
    a.add_argument("--prompt", type=Path, default=PROMPT_PATH)
    a.add_argument("--max-processes", type=int, default=100)
    a.add_argument("--max-markers", type=int, default=500)
    a.add_argument("--max-turns", type=int, default=10)
    a.add_argument("--dry-run", action="store_true",
                   help="Run pipeline + tools locally; no API call.")
    args = parser.parse_args(argv)

    report, report_path = build_report(
        args.capture,
        out=args.report,
        binary=args.binary,
        max_processes=args.max_processes,
        max_markers=args.max_markers,
    )
    print(f"wrote {report_path} ({len(json.dumps(report))} bytes trimmed)")

    if args.dry_run:
        text = dry_run_analysis(report, args.capture)
    else:
        from agentcutter.agent import run_analysis

        system = load_system_prompt(args.prompt)
        text = run_analysis(report, system, args.capture, max_turns=args.max_turns)

    output = args.output or default_output(args.capture)
    output.write_text(text, encoding="utf-8")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
