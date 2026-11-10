# Examples: live-kernel capture + AgentCutter analysis

`live-capture.jsonl` is a real Forkline capture from the host kernel
(7.0.0-42-generic, LSM mode), produced 2026-11-01 to show AgentCutter
working on non-synthetic data.

## Provenance

- `sudo make integration` in `../forkline`: all 4 tests PASS
  (`TestIntegrationLoaderObserveOnly`, `TestIntegrationMultiAgentConcurrent`,
  `TestIntegrationOrphanedChild`, `TestIntegrationAdoption`), zero
  ring-buffer drops, zero map-full counters, no BPF leaks.
- The integration tests assert on temp-dir captures, so persistent data was
  captured separately with the same shape: `/tmp/ac-capture/run.sh` ran the
  loader with `--enable-syscall-summary --syscall-interval 500ms` and a
  `kind: tool` + `interpreter`/`argv_contains` rule matching
  `/tmp/ac-capture/workload.py`, which ran twice (file writes, `true`/`echo`
  children, TCP + UDP connects, sleeps for phase structure).
- Result: 382 marker events, 2 sessions (`demo-agent`), vendored here unchanged.

## Files

- `live-capture.jsonl` — the capture (input).
- `live-capture.report.json` — `agentcutter` reduction (series stripped).
- `live-capture.analysis.md` — Muse Spark analysis with capture-tool verification.
- `live-capture.dryrun.md` — `--dry-run` output (no API call).

## Reproduce

```sh
.venv/bin/agentcutter analyze examples/live-capture.jsonl --dry-run \
  --report examples/live-capture.report.json \
  --output examples/live-capture.dryrun.md
.venv/bin/python -m pytest tests/test_examples.py
```

## Live demo

`demo.sh` + `demo-workload.py`: capture a real agent workload on the host
kernel and analyze it, end to end. Run in a real terminal (sudo needs
the TTY), from the repo root:

```sh
bash examples/demo.sh
```

It rebuilds `bin/forkline-timeline` (and `bin/forkline-scorecard`) when missing
or stale, runs the loader for ~55s with `--enable-syscall-summary` plus
`--enable-file-rw-events` and `--enable-net-send-events` while the
workload runs twice, prints the scorecard and the `forkline-timeline`
summary, then the AgentCutter analysis. Outputs land in `/tmp/ac-demo/`.
`FORKLINE_DIR` overrides the Forkline checkout location.

Before anything is built or captured, the demo shows which credentials
and model the analysis will use and asks whether they are right;
answering no stops it and prints how to set the ones you want. With no
analysis credentials at all it says so and the analysis is a `--dry-run`.

## Analysis credentials and model

Nothing is assumed about which service, key or model you have. AgentCutter
discovers what is available, environment variables ending in `_API_KEY` /
`_AUTH_TOKEN` (except Forkline's coding-agent `AGENT_*`) and key files in
`~/.config/agentcutter/model-credentials/<name>.key`, works out which
service each key belongs to (from its format or name, or a `provider=` /
`base_url=` line in the key file), and lists the rest as unusable with how
to fix them. A key is only ever sent to its own service. Once credentials
are chosen, the models come from that service's `/v1/models`; if it cannot
list them, you type an id.

```sh
agentcutter session list    # credentials found, and which service each is for
agentcutter session pick    # choose credentials + model, save (ids only, no key)
agentcutter session show    # the choice that would be used, and the models offered
agentcutter session check   # test it with a 1-token request
```

`agentcutter analyze` uses `--auth`/`--model` (or `AGENTCUTTER_AUTH` /
`AGENTCUTTER_MODEL`), else the saved choice if still available, else the
only option or a menu, then asks before the analysis runs (`--yes` or
`AGENTCUTTER_CONFIRM=1` skips the question; without a terminal one of them
is required). A rejected key or unknown model is reported in plain words
with the same how-to. Keys are never printed, not even in part.

## Tool spans

`agentcutter analyze` reports per-tool-call spans (Forkline
`forkline-timeline` `tool_spans`) and the analysis ranks tool calls by wall
time and resources. With a Claude Code hook file (Forkline
`hooks/forkline_hook.py`) saved as `<capture>.spans.jsonl`, or passed
with `--spans`, spans carry tool names and inputs. `--agent-process NAME`
re-roots spans for agents started through a wrapper. The tools
`get_tool_spans(session_id, sort_by=wall|cpu|read_bytes|net)` and
`get_span(span_id)` give the model every span, not just the trimmed top.
A real Claude Code run with hooks is canned in Forkline
`examples/canned/` (`make demo-canned` there).
