#!/usr/bin/env bash
# End-to-end demo against local fake SSH devices. Nothing here touches real gear.
#
#   1. start three mock devices (asyncssh servers replaying recorded fixtures)
#   2. back up their configs (one inventory entry is deliberately unreachable)
#   3. "change" access-sw1 and back up again -> unified diff
#   4. run the compliance policies -> JSON + HTML reports
#   5. network health of this host, and the C packet parser on a sample pcap
#
# Env: OUT (default ./demo-out), NEXUS_LAB_HOST (default 127.0.0.1),
#      DEMO_EXTERNAL_DEVICES=1 to skip starting mock devices (docker compose).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/demo-out}"
LAB="${LAB_DIR:-$OUT/lab}"
export NEXUS_PASSWORD="${NEXUS_PASSWORD:-demo-only-$RANDOM$RANDOM}"
INV="$ROOT/examples/inventory.yaml"
step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

rm -rf "$OUT/backups" "$OUT/reports"
mkdir -p "$OUT/reports" "$LAB"

if [[ "${DEMO_EXTERNAL_DEVICES:-0}" != 1 ]]; then
  rm -rf "$LAB"; cp -r "$ROOT/examples/fixtures" "$LAB"
  step "starting mock devices from $LAB"
  nexus mock-devices --fixtures "$LAB" --base-port 2201 &
  MOCK_PID=$!
  trap 'kill $MOCK_PID 2>/dev/null || true' EXIT
fi
for _ in $(seq 50); do
  nexus inventory -i "$INV" -l access-sw1 --probe >/dev/null 2>&1 && break
  sleep 0.2
done

step "nexus inventory --probe"
nexus inventory -i "$INV" --probe || true

step "nexus backup (first run)"
nexus backup -i "$INV" -o "$OUT/backups" --git --retries 1 --backoff 0.2 || true

step "simulating a change on access-sw1, then backing up again"
cp "$ROOT/examples/changes/access-sw1/show_running-config.txt" "$LAB/access-sw1/"
nexus backup -i "$INV" -o "$OUT/backups" --git --show-diff --retries 1 --backoff 0.2 || true

step "nexus comply (live, over SSH)"
nexus comply -i "$INV" -p "$ROOT/examples/policies" --retries 1 --backoff 0.2 \
  --json-out "$OUT/reports/compliance.json" --html-out "$OUT/reports/compliance.html" || true

step "nexus health"
nexus health --interval 1 --fail-on never --json-out "$OUT/reports/health.json"

step "nexus pcap"
nexus pcap "$ROOT/examples/pcap/sample.pcap" --top 5

step "artifacts"
find "$OUT/reports" "$OUT/backups" -maxdepth 1 -type f | sort
