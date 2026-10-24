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
#   ./scripts/compat.sh                 # plaintext dev cluster (default)
#   COMPAT_TLS=1 ./scripts/compat.sh    # mTLS on the data plane (agents+gateway)
#
# TLS mode mints a throwaway CA and certificates into the run's temp dir with
# `fass-gateway pki` (the same stdlib-only CA an operator uses), starts the 12
# agents with --require-mtls and the gateway with --agent-tls=require
# --require-mtls. The coordinator stays plaintext in this dev matrix and the
# gateway opts in explicitly with --coordinator-insecure; the control-plane TLS
# client is covered by unit tests and docs/08. The S3 edge stays HTTP (clients
# are unchanged), so the matrix proves the shard transport, not the frontend.
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
rm -rf "$T"
mkdir -p "$T/disks" "$T/out"
PIDS=()
PG_COMPAT_DB=""
cleanup() {
  for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done; wait 2>/dev/null || true
  if [[ -n "$PG_COMPAT_DB" ]]; then
    psql "${PG_ADMIN_DSN:-}" -q -c "DROP DATABASE IF EXISTS $PG_COMPAT_DB WITH (FORCE)" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

wait_http() { local i; for ((i = 0; i < ${2:-40} * 4; i++)); do curl -sf -m 1 "$1" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }

echo "== build =="
go build -o bin/ ./cmd/... || { echo "build failed"; exit 1; }

TLS_MODE=${COMPAT_TLS:-0}
AGENT_SEC_ARGS=(--insecure)
GW_SEC_ARGS=()
if [[ "$TLS_MODE" == "1" ]]; then
  echo "== data-plane mTLS (COMPAT_TLS=1) =="
  # Throwaway CA + certs in the temp dir; never in the repo. The server cert
  # carries the announcement hostname (agents advertise hostname:port) and the
  # loopback IP so the gateway's per-dial ServerName verifies either way.
  ./bin/fass-gateway pki init --dir "$T/ca" >/dev/null || { echo "pki init failed"; exit 1; }
  ./bin/fass-gateway pki issue-server --ca-dir "$T/ca" --dir "$T/agent" \
    --dns "$(hostname)" --ip 127.0.0.1 --ttl 24h >/dev/null || { echo "pki issue-server failed"; exit 1; }
  ./bin/fass-gateway pki issue-client --ca-dir "$T/ca" --dir "$T/gw" \
    --identity gateway-compat --ttl 24h >/dev/null || { echo "pki issue-client failed"; exit 1; }
  AGENT_SEC_ARGS=(--tls-cert="$T/agent/tls.crt" --tls-key="$T/agent/tls.key" --tls-ca="$T/ca/ca.crt" --require-mtls)
  GW_SEC_ARGS=(--ca-cert="$T/ca/ca.crt" --client-cert="$T/gw/tls.crt" --client-key="$T/gw/tls.key" \
    --agent-tls=require --require-mtls --coordinator-insecure)
fi

echo "== cluster (coordinator dev-bootstrap + 12 agents + gateway) =="
# Optional PostgreSQL backend: set FASS_COMPAT_POSTGRES_DSN to an administrative
# DSN (a database the user can create/drop in). The script creates a fresh
# database per run so stale agents/rings can never leak into the next run.
COORD_DB_ARGS=()
if [[ -n "${FASS_COMPAT_POSTGRES_DSN:-}" ]]; then
  if ! command -v psql >/dev/null; then echo "FASS_COMPAT_POSTGRES_DSN set but psql is not installed"; exit 1; fi
  read -r PG_ADMIN_DSN PG_COMPAT_DB PG_DSN < <(python3 - "$FASS_COMPAT_POSTGRES_DSN" <<'PYDSN'
import sys, time
from urllib.parse import urlsplit, urlunsplit
u = urlsplit(sys.argv[1])
name = "fass_compat_%d" % time.time_ns()
admin = urlunsplit((u.scheme, u.netloc, "/postgres", u.query, u.fragment))
fresh = urlunsplit((u.scheme, u.netloc, "/" + name, u.query, u.fragment))
print(admin, name, fresh)
PYDSN
)
  psql "$PG_ADMIN_DSN" -q -c "CREATE DATABASE $PG_COMPAT_DB" || { echo "could not create $PG_COMPAT_DB"; exit 1; }
  ./bin/fass-coordinator migrate --db-dsn="$PG_DSN" >"$T/migrate.log" 2>&1 || { cat "$T/migrate.log"; exit 1; }
  COORD_DB_ARGS=(--db-driver=postgres --db-dsn="$PG_DSN")
  echo "   coordinator backend: PostgreSQL ($PG_COMPAT_DB)"
fi
./bin/fass-coordinator --listen="127.0.0.1:$COORD" --data-dir="$T/coord" --dev-bootstrap "${COORD_DB_ARGS[@]}" >"$T/coord.log" 2>&1 &
PIDS+=($!)
wait_http "http://127.0.0.1:$COORD/healthz" 40 || { echo "coordinator failed: see $T/coord.log"; exit 1; }
grep -o 'FASS_DEV_BOOTSTRAP .*' "$T/coord.log" | head -1 | cut -d' ' -f2- >"$T/boot.json"

python3 - "$T" "$COORD" "$AGENT" "${AGENT_SEC_ARGS[*]}" >"$T/agents.sh" <<'PY'
import json, sys
tmp, coord, base, sec = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
d = json.load(open(f"{tmp}/boot.json"))
for i, a in enumerate(d["agents"]):
    print(f'./bin/fass-agent --nexus-id={a["nexus_id"]} --node-id={a["node_id"]} '
          f'--disk={tmp}/disks/a{i} --port={base+i} --coordinator-url=http://127.0.0.1:{coord} '
          f'--secret={a["secret"]} --disk-id={a["disk_id"]} --repair=false --scrub=false '
          f'--log-level=warn {sec} >>{tmp}/agent{i}.log 2>&1 & echo $! >>{tmp}/pids')
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
  --default-redundancy-class dev-rc --key-seed "$SEED" "${GW_SEC_ARGS[@]}" >"$T/gw.log" 2>&1 &
PIDS+=($!)
wait_http "http://127.0.0.1:$GWADMIN/healthz" 40 || { echo "gateway failed: see $T/gw.log"; exit 1; }

# The health endpoint must tell the truth about what is encrypted.
SEC=$(curl -sS "http://127.0.0.1:$GWADMIN/healthz")
if [[ "$TLS_MODE" == "1" ]]; then
  echo "$SEC" | grep -q '"insecure":false' && echo "$SEC" | grep -q '"agent_mode":"require"' \
    || { echo "gateway healthz does not report TLS mode: $SEC"; exit 1; }
  echo "   gateway security: $(echo "$SEC" | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin)["security"],sort_keys=True))')"
else
  echo "$SEC" | grep -q '"insecure":true' || { echo "plaintext gateway healthz is not explicit: $SEC"; exit 1; }
fi

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

  # Tree sync: a directory with a mix of sizes, synced up and back. This is the
  # shape real backup tools use; it stresses listing, deletes and multipart
  # together rather than one file at a time.
  mkdir -p "$T/tree/a" "$T/tree/b"
  head -c 1024 /dev/urandom >"$T/tree/small.bin"
  head -c 300000 /dev/urandom >"$T/tree/a/medium.bin"
  head -c 12000000 /dev/urandom >"$T/tree/b/large.bin"
  if "${A[@]}" s3 sync "$T/tree" s3://compat-aws/sync/ --only-show-errors >/dev/null 2>"$T/aws-sync.err"; then
    pass "sync up (tree incl. multipart)"
  else
    fail "sync up: $(tail -1 "$T/aws-sync.err")"
  fi
  mkdir -p "$T/out/aws-sync"
  "${A[@]}" s3 sync s3://compat-aws/sync/ "$T/out/aws-sync" --only-show-errors >/dev/null 2>&1
  if diff -r "$T/tree" "$T/out/aws-sync" >/dev/null 2>&1; then pass "sync down (tree byte-identical)"; else fail "sync down (tree differs)"; fi
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
  if "$RCLONE_BIN" sync "$T/tree" c:compat-aws/rclone-sync --s3-upload-cutoff 5M --s3-chunk-size 5M -q 2>"$T/rclone-sync.err"; then
    pass "sync up (tree incl. multipart)"
  else
    fail "sync up: $(tail -1 "$T/rclone-sync.err")"
  fi
  if "$RCLONE_BIN" check "$T/tree" c:compat-aws/rclone-sync -q 2>"$T/rclone-check.err"; then
    pass "check (hashes match server-side)"
  else
    fail "check: $(tail -1 "$T/rclone-check.err")"
  fi
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
if [[ $FAIL -eq 0 ]]; then
  echo "COMPAT: PASS ($([[ "$TLS_MODE" == "1" ]] && echo "data plane mTLS" || echo "data plane plaintext, --insecure"))"
  [[ "${COMPAT_KEEP:-0}" == "1" ]] || rm -rf "$T"
else
  echo "COMPAT: FAIL (logs in $T)"
fi
exit $FAIL
