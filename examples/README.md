# Examples: live-kernel capture + AgentCutter analysis

`live-capture.jsonl` is a real AgentLoupe capture from the host kernel
(7.0.0-42-generic, LSM mode), produced 2026-11-01 to show AgentCutter
working on non-synthetic data.

## Provenance

- `sudo make integration` in `../AgentLoupe`: all 4 tests PASS
  (`TestIntegrationLoaderObserveOnly`, `TestIntegrationMultiAgentConcurrent`,
  `TestIntegrationOrphanedChild`, `TestIntegrationAdoption`), zero
  ring-buffer drops, zero map-full counters, no BPF leaks.
- The integration tests assert on temp-dir captures, so persistent data was
  captured separately with the same shape: `/tmp/ac-capture/run.sh` ran the
  loader with `--enable-syscall-summary --syscall-interval 500ms` and a
  `kind: tool` + `interpreter`/`argv_contains` rule matching
  `/tmp/ac-capture/workload.py`, which ran twice (file writes, `true`/`echo`
  children, TCP + UDP connects, sleeps for phase structure).
- Result: 382 events, 2 sessions (`demo-agent`), vendored here unchanged.

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

It rebuilds `bin/loupe-timeline` (and `bin/loupe-scorecard`) when missing
or stale, runs the loader for ~55s with `--enable-syscall-summary` plus
`--enable-file-rw-events` and `--enable-net-send-events` while the
workload runs twice, prints the scorecard and the `loupe-timeline`
summary, then the AgentCutter analysis (real Muse Spark call if
`META_MODEL_API_KEY` is set, `--dry-run` otherwise). Outputs land
in `/tmp/ac-demo/`. `LOUPE_DIR` overrides the AgentLoupe checkout location.

Note: `live-capture.jsonl` was taken with `--enable-syscall-summary` only,
so it holds no `file_read`/`file_write`/`net_send`/`net_recv` events —
byte/hostname fields are absent there and the analysis says so. Fresh
`demo.sh` captures include them.
