#!/usr/bin/env bash
# Third-party S3 compatibility matrix against a live FASS cluster.
#
# Rationale: our own SDK passed while multipart was completely broken (see
# docs/06 risk R6 — real clients found what our tests could not). This script
# exists so compatibility is a repeatable gate, not an anecdote.
#
# Clients are optional and detected at runtime:
#   - aws-cli   (.dev/venv/bin/aws or $PATH)
#   - rclone    (.dev/rclone or $PATH)
#   - s3cmd     (.dev/venv/bin/s3cmd or $PATH)
#
#   ./scripts/compat.sh
#
# Exit code is non-zero if any *detected* client fails a check.
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FAIL=0
pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; FAIL=1; }
skip() { echo "  SKIP  $*"; }

AWS_BIN=$(command -v aws 2>/dev/null || echo .dev/venv/bin/aws)
RCLONE_BIN=$(command -v rclone 2>/dev/null || echo .dev/rclone)
S3CMD_BIN=$(command -v s3cmd 2>/dev/null || echo .dev/venv/bin/s3cmd)
[[ -x "$AWS_BIN" ]] || AWS_BIN=""
[[ -x "$RCLONE_BIN" ]] || RCLONE_BIN=""
[[ -x "$S3CMD_BIN" ]] || S3CMD_BIN=""

BASE=$((20000 + RANDOM % 400 * 10))
COORD=$BASE
GW=$((BASE + 1))
GWADMIN=$((BASE + 2))
AGENT=$((BASE + 50))
T=.dev/compat-$$
mkdir -p "$T/disks" "$T/out"
PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT

wait_http() { local i; for ((i = 0; i < ${2:-40} * 4; i++)); do curl -sf -m 1 "$1" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }

echo "== build =="
go build -o bin/ ./cmd/... || { echo "build failed"; exit 1; }

echo "== cluster (coordinator dev-bootstrap + 12 agents + gateway) =="
./bin/fass-coordinator --listen="127.0.0.1:$COORD" --data-dir="$T/coord" --dev-bootstrap >"$T/coord.log" 2>&1 &
PIDS+=($!)
wait_http "http://127.0.0.1:$COORD/healthz" 40 || { echo "coordinator failed: see $T/coord.log"; exit 1; }
grep -o 'FASS_DEV_BOOTSTRAP .*' "$T/coord.log" | head -1 | cut -d' ' -f2- >"$T/boot.json"

python3 - "$T" "$COORD" "$AGENT" >"$T/agents.sh" <<'PY'
import json, sys
tmp, coord, base = sys.argv[1], sys.argv[2], int(sys.argv[3])
d = json.load(open(f"{tmp}/boot.json"))
for i, a in enumerate(d["agents"]):
    print(f'./bin/fass-agent --nexus-id={a["nexus_id"]} --node-id={a["node_id"]} '
          f'--disk={tmp}/disks/a{i} --port={base+i} --coordinator-url=http://127.0.0.1:{coord} '
          f'--secret={a["secret"]} --disk-id={a["disk_id"]} --repair=false --scrub=false '
          f'--log-level=warn >>{tmp}/agent{i}.log 2>&1 & echo $! >>{tmp}/pids')
PY
bash "$T/agents.sh"
PIDS+=($(cat "$T/pids" 2>/dev/null))

# Activation must wait for announce, not just for records to exist: activating an
# unannounced agent permanently consumes its one-time secret.
for _ in $(seq 1 80); do
  N=$(curl -sS "http://127.0.0.1:$COORD/v1/agents" 2>/dev/null |
    python3 -c 'import sys,json;ag=json.load(sys.stdin).get("agents") or [];print(sum(1 for a in ag if a.get("endpoint")))' 2>/dev/null || echo 0)
  [[ "$N" == "12" ]] && break
  sleep 0.25
done
for id in $(curl -sS "http://127.0.0.1:$COORD/v1/agents" |
  python3 -c 'import sys,json;[print(a["agent_id"]) for a in (json.load(sys.stdin).get("agents") or []) if a.get("state")!="active"]'); do
  curl -sS -X POST "http://127.0.0.1:$COORD/v1/agents/$id/activate" >/dev/null
done

SEED=$(python3 -c 'import secrets;print(secrets.token_hex(32))')
./bin/fass-gateway --coordinator="http://127.0.0.1:$COORD" --listen="127.0.0.1:$GW" \
  --admin-listen="127.0.0.1:$GWADMIN" --dev --region=eu-west-1 \
  --geo-n 2 --geo-k 1 --local-n 3 --local-k 1 --chunk-size 6291456 \
  --default-redundancy-class dev-rc --key-seed "$SEED" >"$T/gw.log" 2>&1 &
PIDS+=($!)
wait_http "http://127.0.0.1:$GWADMIN/healthz" 40 || { echo "gateway failed: see $T/gw.log"; exit 1; }

export AWS_ACCESS_KEY_ID=dev-access-key AWS_SECRET_ACCESS_KEY=dev-secret-key AWS_DEFAULT_REGION=eu-west-1
export AWS_EC2_METADATA_DISABLED=true
EP="http://127.0.0.1:$GW"
head -c 14680064 /dev/urandom >"$T/in.bin" # 14 MiB -> multipart at 5-8 MiB thresholds

# --- aws-cli -------------------------------------------------------------
if [[ -n "$AWS_BIN" ]]; then
  echo "== aws-cli ($("$AWS_BIN" --version 2>&1 | head -1)) =="
  A=("$AWS_BIN" --endpoint-url "$EP")
  "${A[@]}" s3api create-bucket --bucket compat-aws >/dev/null 2>&1
  if "${A[@]}" s3 cp "$T/in.bin" s3://compat-aws/dir/big.bin --only-show-errors >/dev/null 2>"$T/aws-up.err"; then
    pass "put 14 MiB (multipart)"
  else
    fail "put 14 MiB: $(tail -1 "$T/aws-up.err")"
  fi
  if "${A[@]}" s3 ls s3://compat-aws/dir/ 2>/dev/null | grep -q big.bin; then pass "list objects"; else fail "list objects"; fi
  "${A[@]}" s3 cp s3://compat-aws/dir/big.bin "$T/out/aws.bin" --only-show-errors >/dev/null 2>&1
  if cmp -s "$T/in.bin" "$T/out/aws.bin"; then pass "get byte-identical"; else fail "get byte-identical"; fi
  if "${A[@]}" s3api list-buckets >/dev/null 2>&1; then pass "list buckets (strict SDK parse)"; else fail "list buckets"; fi
else
  skip "aws-cli not installed"
fi

# --- rclone --------------------------------------------------------------
if [[ -n "$RCLONE_BIN" ]]; then
  echo "== rclone ($("$RCLONE_BIN" version 2>&1 | head -1)) =="
  export RCLONE_CONFIG_C_TYPE=s3 RCLONE_CONFIG_C_PROVIDER=Other \
    RCLONE_CONFIG_C_ACCESS_KEY_ID=dev-access-key RCLONE_CONFIG_C_SECRET_ACCESS_KEY=dev-secret-key \
    RCLONE_CONFIG_C_ENDPOINT="$EP" RCLONE_CONFIG_C_REGION=eu-west-1 RCLONE_CONFIG_C_FORCE_PATH_STYLE=true
  if "$RCLONE_BIN" lsd c: >/dev/null 2>"$T/rclone-lsd.err"; then
    pass "lsd (aws-sdk-go-v2 time parse)"
  else
    fail "lsd: $(tail -1 "$T/rclone-lsd.err")"
  fi
  if "$RCLONE_BIN" copy "$T/in.bin" c:compat-aws/rclone/ --s3-upload-cutoff 5M --s3-chunk-size 5M -q 2>"$T/rclone-up.err"; then
    pass "copy up 14 MiB (multipart)"
  else
    fail "copy up: $(tail -1 "$T/rclone-up.err")"
  fi
  mkdir -p "$T/out/rclone"
  "$RCLONE_BIN" copy c:compat-aws/rclone/in.bin "$T/out/rclone" -q 2>/dev/null
  if cmp -s "$T/in.bin" "$T/out/rclone/in.bin"; then pass "copy down byte-identical"; else fail "copy down byte-identical"; fi
else
  skip "rclone not installed"
fi

# --- s3cmd ---------------------------------------------------------------
if [[ -n "$S3CMD_BIN" ]]; then
  echo "== s3cmd ($("$S3CMD_BIN" --version 2>&1 | head -1)) =="
  cat >"$T/s3cfg" <<EOF
[default]
access_key = dev-access-key
secret_key = dev-secret-key
host_base = 127.0.0.1:$GW
host_bucket = 127.0.0.1:$GW
use_https = False
signature_v2 = False
bucket_location = eu-west-1
EOF
  S=("$S3CMD_BIN" -c "$T/s3cfg")
  if "${S[@]}" put "$T/in.bin" s3://compat-aws/s3cmd/big.bin --multipart-chunk-size-mb=5 -q >/dev/null 2>"$T/s3cmd-up.err"; then
    pass "put 14 MiB (multipart)"
  else
    fail "put: $(tail -1 "$T/s3cmd-up.err")"
  fi
  if "${S[@]}" ls s3://compat-aws/ 2>/dev/null | grep -q s3cmd; then pass "ls"; else fail "ls"; fi
  "${S[@]}" get s3://compat-aws/s3cmd/big.bin "$T/out/s3cmd.bin" -q >/dev/null 2>&1
  if cmp -s "$T/in.bin" "$T/out/s3cmd.bin"; then pass "get byte-identical"; else fail "get byte-identical"; fi
else
  skip "s3cmd not installed"
fi

echo
if [[ $FAIL -eq 0 ]]; then echo "COMPAT: PASS"; else echo "COMPAT: FAIL (logs in $T)"; fi
exit $FAIL
