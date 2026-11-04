#!/bin/bash
# Live demo: capture a real agent workload with AgentLoupe, analyze it
# with AgentCutter, print the analysis. End to end on the host kernel.
#
# Run in a real terminal (sudo needs the TTY), from anywhere:
#   bash examples/demo.sh
#
# Env:
#   LOUPE_DIR  AgentLoupe checkout (default: <agentcutter>/../AgentLoupe)
#   META_MODEL_API_KEY  if set, runs the real Muse Spark analysis;
#                       otherwise runs --dry-run (no API call).
set -euo pipefail

ACUTTER="$(cd "$(dirname "$0")/.." && pwd)"
LOUPE_DIR="${LOUPE_DIR:-$(cd "$ACUTTER/../AgentLoupe" && pwd)}"
STAGE=/tmp/ac-demo
mkdir -p "$STAGE"
OUT=$STAGE/demo-capture.jsonl
PY=$(readlink -f "$(command -v python3)")

build_tool() {
  # $1 = cmd dir, $2 = output binary. Rebuild when missing or stale.
  if [ ! -x "$2" ] || [ "$LOUPE_DIR/cmd/$1/main.go" -nt "$2" ]; then
    (cd "$LOUPE_DIR" && go build -buildvcs=false -o "$2" "./cmd/$1")
  fi
}

echo "== 1/4 build loader + loupe-timeline + loupe-scorecard"
# The loader binary must match the BPF object (ABI): a stale agentloupe
# decodes nothing ("abi version X, want Y" in the loader output) and the
# capture comes out empty even though kernel counters show events flowing.
if [ ! -x "$LOUPE_DIR/agentloupe" ] \
  || [ "$LOUPE_DIR/cmd/agentloupe/main.go" -nt "$LOUPE_DIR/agentloupe" ] \
  || [ "$LOUPE_DIR/bpf/agentloupe.bpf.c" -nt "$LOUPE_DIR/agentloupe" ] \
  || [ "$LOUPE_DIR/bpf/agentloupe.h" -nt "$LOUPE_DIR/agentloupe" ]; then
  make -C "$LOUPE_DIR" build
fi
build_tool loupe-timeline "$ACUTTER/bin/loupe-timeline"
build_tool loupe-scorecard "$ACUTTER/bin/loupe-scorecard"

echo "== 2/4 capture live agent workload (needs sudo for the loader)"
sudo -v
cat > "$STAGE/agents.yaml" <<EOF
agents:
  - name: demo-agent
    kind: tool
    match:
      interpreter: $PY
      argv_contains: agentcutter-demo
EOF
# --enable-file-rw-events + --enable-net-send-events so the analysis can
# show per-call byte counts, send/recv volume, and hostnames (empty on
# loopback, which the analysis should say rather than guess about).
sudo "$LOUPE_DIR/agentloupe" \
  --config "$STAGE/agents.yaml" \
  --bpf-object "$LOUPE_DIR/bpf/agentloupe.bpf.o" \
  --enable-syscall-summary --syscall-interval 500ms \
  --enable-file-rw-events --enable-net-send-events \
  --max-runtime 55s --output "$OUT" &
LOADER=$!
sleep 6
python3 "$ACUTTER/examples/demo-workload.py" agentcutter-demo-run1
sleep 15
python3 "$ACUTTER/examples/demo-workload.py" agentcutter-demo-run2
wait "$LOADER"
sudo chown "$USER:$USER" "$OUT"
wc -l "$OUT"
if [ ! -s "$OUT" ]; then
  echo "demo: ERROR: capture $OUT is empty — nothing was decoded." >&2
  echo "demo: see the loader output above: 'abi version X, want Y' means a" >&2
  echo "demo: stale loader binary (fix: make -C \"$LOUPE_DIR\" build);" >&2
  echo "demo: 'no agent sessions seen' means the agents.yaml rule matched nothing." >&2
  exit 1
fi

CUTTER="$ACUTTER/.venv/bin/agentcutter"
[ -x "$CUTTER" ] || CUTTER="agentcutter"

echo "== 3/4 scorecard + timeline summary"
"$ACUTTER/bin/loupe-scorecard" "$OUT"
"$ACUTTER/bin/loupe-timeline" "$OUT" | head -30

echo "== 4/4 AgentCutter analysis"
if [ -z "${META_MODEL_API_KEY:-}" ]; then
  echo "(no META_MODEL_API_KEY: dry run, no API call)"
  "$CUTTER" analyze "$OUT" --dry-run \
    --report "$STAGE/demo-capture.report.json" \
    --output "$STAGE/demo-capture.analysis.md"
else
  "$CUTTER" analyze "$OUT" \
    --report "$STAGE/demo-capture.report.json" \
    --output "$STAGE/demo-capture.analysis.md"
fi
echo "--- analysis ($STAGE/demo-capture.analysis.md):"
cat "$STAGE/demo-capture.analysis.md"
