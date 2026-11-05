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


def _syscalls_total(session: dict) -> int:
    """Explicit syscall denominator: annotated, else summed from the table."""
    if session.get("syscalls_total") is not None:
        return session["syscalls_total"]
    return sum(
        c.get("count", 0)
        for c in (session.get("syscall_distribution") or [])
        if isinstance(c, dict)
    )


def dry_run_analysis(report: dict, capture: Path, tool_opts: dict | None = None) -> str:
    """Deterministic no-API analysis: exercises pipeline + every tool."""
    tool_opts = tool_opts or {}
    lines = ["# AgentCutter dry-run analysis", ""]
    lines.append(f"Capture: `{capture}` (no API call made)")
    lines.append("")
    for s in report.get("sessions", []):
        sid = s.get("session_id")
        end = s.get("session_end_reason") or "?"
        lines.append(
            f"## Session {sid} ({s.get('agent')}, "
            f"duration {s.get('duration_ms')}ms, {s.get('events')} marker events, "
            f"{_syscalls_total(s)} syscalls, end {end})"
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
        lines.append(
            f"- network connects: {net['total_connects']}, "
            f"sends: {net['sends']} ({net['sent_bytes']} bytes), "
            f"recvs: {net['recvs']} ({net['recv_bytes']} bytes)"
        )
        if net["hostnames"]:
            lines.append(f"- hostnames: {', '.join(net['hostnames'])}")
        if net["first_response_us"]:
            lines.append(
                f"- first send->recv latency: {net['first_response_us']}us"
            )
        files = capture_tools.files_opened(capture, sid)
        lines.append(
            f"- file events: {files['total_matching']} "
            f"(reads: {files['file_read_calls']}, writes: {files['file_write_calls']}, "
            f"read bytes: {files['read_bytes']}, written: {files['write_bytes']})"
        )
        spans = capture_tools.get_tool_spans(capture, sid, sort_by="wall", limit=5, **tool_opts)
        if spans.get("spans") is not None:
            recon = (spans.get("reconciliation") or {}).get("ok")
            lines.append(
                f"- tool spans: {spans['total_spans']} "
                f"(sum(spans)+agent_self == totals: {'yes' if recon else 'NO'})"
            )
            for sp in spans["spans"]:
                cpu = sp.get("cpu_ms")
                lines.append(
                    f"  - {sp['span_id']} {sp.get('what')}: wall {sp.get('wall_ms')}ms, "
                    f"cpu {cpu if cpu is not None else 'n/a'}ms, "
                    f"opens {sp.get('file_opens')}, read_bytes {sp.get('read_bytes', 'n/a')}"
                    + (f" [{sp.get('attribution')}]" if sp.get("attribution") == "time_window" else "")
                )
            for g in spans.get("repeated") or []:
                lines.append(
                    f"  - repeated x{g['count']}: `{g['what']}` ({g['total_wall_ms']}ms total)"
                )
            first = (spans["spans"] or [None])[0]
            if first:
                detail = capture_tools.get_span(capture, first["span_id"], **tool_opts)
                lines.append(
                    f"  - costliest span detail: {len(detail.get('top_files') or [])} top files, "
                    f"{len(detail.get('top_destinations') or [])} destinations"
                )
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
    a.add_argument("--spans", type=Path, default=None,
                   help="Harness hook spans JSONL (default: <capture>.spans.jsonl if present).")
    a.add_argument("--agent-process", default=None,
                   help="Process tool spans hang off (for wrapped agents); default: session root.")
    a.add_argument("--max-tool-spans", type=int, default=40)
    a.add_argument("--dry-run", action="store_true",
                   help="Run pipeline + tools locally; no API call.")
    args = parser.parse_args(argv)

    report, report_path = build_report(
        args.capture,
        out=args.report,
        binary=args.binary,
        max_processes=args.max_processes,
        max_markers=args.max_markers,
        spans=args.spans,
        agent_process=args.agent_process,
        max_tool_spans=args.max_tool_spans,
    )
    tool_opts = {"spans": args.spans, "agent_process": args.agent_process, "binary": args.binary}
    print(f"wrote {report_path} ({len(json.dumps(report))} bytes trimmed)")

    if args.dry_run:
        text = dry_run_analysis(report, args.capture, tool_opts)
    else:
        from agentcutter.agent import run_analysis

        system = load_system_prompt(args.prompt)
        text = run_analysis(report, system, args.capture, max_turns=args.max_turns,
                            tool_opts=tool_opts)

    output = args.output or default_output(args.capture)
    output.write_text(text, encoding="utf-8")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
