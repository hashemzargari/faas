#!/usr/bin/env bash
# Manual 3-Nexus smoke test — the recipe the end-to-end test automates.
#
# Boots a real cluster on one host (coordinator + 12 agents + gateway), uploads
# a 14 MiB object (3 chunks at the 6 MiB dev chunk size), then optionally kills
# an entire Nexus and reads the object back to prove geo-level reconstruction.
#
#   ./scripts/smoke-cluster.sh            # upload + read
#   ./scripts/smoke-cluster.sh --nexus-loss   # upload + kill nexus-c + read
#
# Requires: source scripts/env.sh (or `make build` first).
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NEXUS_LOSS=0
[[ "${1:-}" == "--nexus-loss" ]] && NEXUS_LOSS=1

BASE=$((17000 + RANDOM % 500 * 10))
COORD_PORT=$BASE
GW_PORT=$((BASE + 1))
GW_ADMIN=$((BASE + 2))
AGENT_BASE=$((BASE + 50))
TMP=.dev/smoke-$$
mkdir -p "$TMP/disks"
trap 'cleanup' EXIT

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
now() { date +%s%3N; }
wait_http() { # url, timeout-seconds
  local url=$1 limit=$2 i
  for ((i = 0; i < limit * 4; i++)); do
    curl -sf -m 1 "$url" >/dev/null 2>&1 && return 0
    sleep 0.25
  done
  echo "timed out waiting for $url" >&2
  return 1
}

echo "== build =="
go build -o bin/ ./cmd/...

echo "== coordinator (dev bootstrap, D′: 12 agents, geo 2+1 / local 3+1) =="
./bin/fass-coordinator --listen="127.0.0.1:$COORD_PORT" --data-dir="$TMP/coord" --dev-bootstrap \
  >"$TMP/coord.log" 2>&1 &
PIDS+=($!)
wait_http "http://127.0.0.1:$COORD_PORT/healthz" 30

grep -o 'FASS_DEV_BOOTSTRAP .*' "$TMP/coord.log" | head -1 | cut -d' ' -f2- >"$TMP/boot.json"
AGENTS=$(python3 -c 'import json;print(len(json.load(open("'"$TMP"'/boot.json"))["agents"]))')
echo "   bootstrap declares $AGENTS agents"

echo "== agents =="
python3 - "$TMP" "$COORD_PORT" "$AGENT_BASE" >"$TMP/agents.sh" <<'PY'
import json, sys
tmp, coord, base = sys.argv[1], sys.argv[2], int(sys.argv[3])
d = json.load(open(f"{tmp}/boot.json"))
lines = []
for i, a in enumerate(d["agents"]):
    lines.append(
        f'./bin/fass-agent --nexus-id={a["nexus_id"]} --node-id={a["node_id"]} '
        f'--disk={tmp}/disks/a{i} --port={base+i} --coordinator-url=http://127.0.0.1:{coord} '
        f'--secret={a["secret"]} --disk-id={a["disk_id"]} --repair=false --scrub=false '
        f'--log-level=warn >>{tmp}/agent{i}.log 2>&1 & echo $! >>{tmp}/pids'
    )
print("\n".join(lines))
PY
bash "$TMP/agents.sh"
PIDS+=($(cat "$TMP/pids"))
sleep 3

# Agents announce into `pending`; an operator activates them (Cubbit's flow).
for id in $(curl -sS "http://127.0.0.1:$COORD_PORT/v1/agents" |
  python3 -c 'import sys,json;[print(a["agent_id"]) for a in (json.load(sys.stdin).get("agents") or []) if a.get("state")!="active"]'); do
  curl -sS -X POST "http://127.0.0.1:$COORD_PORT/v1/agents/$id/activate" >/dev/null
done
sleep 1
ACTIVE=$(curl -sS "http://127.0.0.1:$COORD_PORT/v1/agents" |
  python3 -c 'import sys,json;ag=json.load(sys.stdin).get("agents") or [];print(sum(1 for a in ag if a.get("state")=="active"))')
echo "   active agents: $ACTIVE/$AGENTS"
[[ "$ACTIVE" -eq "$AGENTS" ]] || { echo "agents failed to activate; see $TMP/agent*.log" >&2; exit 1; }

echo "== gateway =="
./bin/fass-gateway --coordinator="http://127.0.0.1:$COORD_PORT" --listen="127.0.0.1:$GW_PORT" \
  --admin-listen="127.0.0.1:$GW_ADMIN" --dev --region=eu-west-1 \
  --geo-n 2 --geo-k 1 --local-n 3 --local-k 1 --chunk-size 6291456 \
  --default-redundancy-class dev-rc >"$TMP/gw.log" 2>&1 &
PIDS+=($!)
wait_http "http://127.0.0.1:$GW_ADMIN/healthz" 30

echo "== upload 14 MiB (3 chunks) =="
OUT=$(go run ./test/smoke upload "http://127.0.0.1:$GW_PORT" dev-access-key dev-secret-key)
echo "$OUT" | sed 's/^/   /'
BUCKET=$(echo "$OUT" | grep -o 'BUCKET=.*' | cut -d= -f2)

if [[ $NEXUS_LOSS -eq 1 ]]; then
  echo "== kill nexus-c (whole site) =="
  # bootstrap order is nexus-a x4, nexus-b x4, nexus-c x4
  for p in $(sed -n '9,12p' "$TMP/pids"); do kill -9 "$p" 2>/dev/null || true; done
  sleep 2
fi

echo "== read back =="
T0=$(now)
go run ./test/smoke verify "http://127.0.0.1:$GW_PORT" dev-access-key dev-secret-key "$BUCKET"
T1=$(now)
echo "   wall time: $((T1 - T0)) ms"
echo "== PASS${NEXUS_LOSS:+ (with one Nexus destroyed)} =="
