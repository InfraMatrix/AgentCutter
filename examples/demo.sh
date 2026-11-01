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

echo "== 1/4 build loupe-timeline"
if [ ! -x "$ACUTTER/bin/loupe-timeline" ]; then
  (cd "$LOUPE_DIR" && go build -buildvcs=false -o "$ACUTTER/bin/loupe-timeline" ./cmd/loupe-timeline)
fi

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
sudo "$LOUPE_DIR/agentloupe" \
  --config "$STAGE/agents.yaml" \
  --bpf-object "$LOUPE_DIR/bpf/agentloupe.bpf.o" \
  --enable-syscall-summary --syscall-interval 500ms \
  --max-runtime 55s --output "$OUT" &
LOADER=$!
sleep 6
python3 "$ACUTTER/examples/demo-workload.py" agentcutter-demo-run1
sleep 15
python3 "$ACUTTER/examples/demo-workload.py" agentcutter-demo-run2
wait "$LOADER"
sudo chown "$USER:$USER" "$OUT"
wc -l "$OUT"

CUTTER="$ACUTTER/.venv/bin/agentcutter"
[ -x "$CUTTER" ] || CUTTER="agentcutter"

echo "== 3/4 timeline summary"
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
