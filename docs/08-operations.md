# 08 — Operations: dev cluster, `fass` CLI and `fass-console`

This is the operator-facing guide for the two surfaces delivered in this
workstream:

* **`fass`** (`cmd/fass-cli`) — an S3 client plus read-only cluster admin CLI.
* **`fass-console`** (`cmd/fass-console`) — a server-rendered web console with
  HTMX, embedded assets and no Node toolchain.

Both are **separate processes**. The console talks to the coordinator over its
documented HTTP+JSON API only (it never imports `internal/coord` or
`internal/gateway`), so it works unchanged against a remote control plane.

> Status: dev-grade. Authentication is a single shared Basic credential and
> there is no RBAC, OIDC/SAML or audit log yet — see
> [Known limitations](#known-limitations).

---

## 1. Ports and defaults

| Component | Default address | Configured by |
|---|---|---|
| Coordinator | `:7000` | `fass-coordinator --listen` |
| Gateway (S3) | `:8080` | `fass-gateway --listen` |
| Gateway admin (`/healthz`, `/readyz`, `/metrics`) | `:9000` | `fass-gateway --admin-listen` |
| Agent shard server | `:7100` | `fass-agent --port` |
| Console | `127.0.0.1:8081` | `fass-console --listen` |

The CLI's built-in defaults match this dev layout: S3 endpoint
`http://127.0.0.1:8080`, coordinator `http://127.0.0.1:7000`, region
`eu-west-1`.

---

## 2. Boot a dev cluster

### 2.1 Prerequisites

```bash
cd /path/to/fass
source scripts/env.sh          # workspace-local GOPATH/GOCACHE, -mod=vendor
make build test                # builds bin/, runs unit tests
```

The sandbox (and the repo) never needs network: dependencies are vendored.

### 2.2 One command (smoke)

```bash
./scripts/smoke-cluster.sh              # upload + read
./scripts/smoke-cluster.sh --nexus-loss # kill a whole Nexus, then read
```

This boots a real coordinator + 12 agents + gateway, uploads 14 MiB and reads it
back; `--nexus-loss` SIGKILLs every `nexus-c` agent first and proves the read
still succeeds through `geo_n = 2`.

### 2.3 Step by step (what the script does, for debugging)

```bash
source scripts/env.sh
make build

# 1. Coordinator with the deterministic dev topology. It prints one line:
#    FASS_DEV_BOOTSTRAP {"access_key_id":"dev-access-key",...,"agents":[12]...}
#    and writes the same JSON to <data-dir>/dev-bootstrap.json.
./bin/fass-coordinator --listen=127.0.0.1:7000 \
  --data-dir=.dev/coord --dev-bootstrap >.dev/coord.log 2>&1 &
grep -o 'FASS_DEV_BOOTSTRAP .*' .dev/coord.log | cut -d' ' -f2- >.dev/boot.json

# 2. One agent per disk (12 total: 6 nodes × 2 disks, 2 nodes per Nexus).
#    --secret is the one-time announce secret from boot.json; --disk-id is the
#    operator-facing slot label ("disk-a1-1"), not the agent identity.
python3 - <<'PY' >.dev/agents.sh
import json
d = json.load(open(".dev/boot.json"))
for i, a in enumerate(d["agents"]):
    print(f'./bin/fass-agent --nexus-id={a["nexus_id"]} --node-id={a["node_id"]} '
          f'--disk=.dev/disks/a{i} --port={7100+i} --coordinator-url=http://127.0.0.1:7000 '
          f'--secret={a["secret"]} --disk-id={a["disk_id"]} --repair=false --scrub=false &')
PY
bash .dev/agents.sh

# 3. Activate each announced agent. Agents announce as `pending` on purpose:
#    activation is the operator's explicit approval step.
for id in $(curl -sS http://127.0.0.1:7000/v1/agents |
  python3 -c 'import sys,json;[print(a["agent_id"]) for a in json.load(sys.stdin)["agents"] if a["state"]!="active"]'); do
  curl -sS -X POST "http://127.0.0.1:7000/v1/agents/$id/activate" >/dev/null
done

# 4. Gateway. The coding parameters must match dev-rc from the bootstrap
#    (geo 2+1 / local 3+1, 6 MiB chunks).
./bin/fass-gateway --coordinator=http://127.0.0.1:7000 \
  --listen=127.0.0.1:8080 --admin-listen=127.0.0.1:9000 --dev \
  --region=eu-west-1 --geo-n 2 --geo-k 1 --local-n 3 --local-k 1 \
  --chunk-size 6291456 --default-redundancy-class dev-rc >.dev/gw.log 2>&1 &

# 5. Console (writes enabled; omit --read-only=false for read-only).
./bin/fass-console --listen=127.0.0.1:8081 \
  --coordinator=http://127.0.0.1:7000 \
  --console-user=admin --console-password=change-me \
  --read-only=false >.dev/console.log 2>&1 &
```

Dev credentials are `dev-access-key` / `dev-secret-key`, region `eu-west-1`,
bucket `dev-bucket`, RC `dev-rc`, ring `dev-ring`.

Stop everything with `kill` on the PIDs (the smoke script does it in a `trap`).
The coordinator's SQLite store lives in `--data-dir`; delete it for a clean
slate.

---

## 3. `fass` CLI

### 3.1 Build and install

```bash
make cli                # -> bin/fass
make console            # -> bin/fass-console
# optional
install -m 0755 bin/fass ~/.local/bin/fass
```

`make build` also produces `bin/fass-cli` and `bin/fass-console` (named after
the command directories); `make cli` installs the operator-facing name `fass`.

### 3.2 Configuration

Precedence: **command-line flag > environment > selected profile > built-in
default**.

Config file: `~/.fass/config` (override with `--config` / `FASS_CONFIG`),
INI-style with profiles:

```ini
[default]
endpoint    = http://127.0.0.1:8080
region      = eu-west-1
access_key  = dev-access-key
secret_key  = dev-secret-key
coordinator = http://127.0.0.1:7000
timeout     = 60s

[prod]
endpoint    = https://s3.prod.example.com
region      = eu-west-1
access_key  = AKIA...
secret_key  = ...
coordinator = https://coordinator.prod.example.com
timeout     = 5m
```

Select a profile with `--profile prod` or `FASS_PROFILE=prod`.

| Flag | Environment | Meaning | Default |
|---|---|---|---|
| `--endpoint` | `FASS_ENDPOINT` | S3 gateway URL | `http://127.0.0.1:8080` |
| `--region` | `FASS_REGION` (`AWS_REGION`) | signing region | `eu-west-1` |
| `--access-key` | `FASS_ACCESS_KEY_ID` (`AWS_ACCESS_KEY_ID`) | access key id | — |
| `--secret` / `--secret-key` | `FASS_SECRET_ACCESS_KEY` (`AWS_SECRET_ACCESS_KEY`) | secret key | — |
| `--coordinator` | `FASS_COORDINATOR_URL` | coordinator base URL | `http://127.0.0.1:7000` |
| `--profile` | `FASS_PROFILE` | config profile | `default` |
| `--config` | `FASS_CONFIG` | config file path | `~/.fass/config` |
| `--timeout` | `FASS_TIMEOUT` | per-request timeout | `60s` |
| `--json` | — | JSON output | table output |
| `--quiet` | — | suppress progress lines | off |

S3 commands require credentials. Admin commands (`health`, `cluster`,
`node`, `rc`, `repair`, `gc`) need only `--coordinator`.

### 3.3 S3 commands (implemented with `pkg/sdk`, SigV4 is never duplicated)

```bash
fass ls                                     # list buckets
fass ls s3://dev-bucket/ops/               # list objects under a prefix
fass cp ./file.bin s3://dev-bucket/ops/file.bin
fass cp s3://dev-bucket/ops/file.bin ./file.bin
fass cp -r ./tree s3://dev-bucket/backup/  # directory upload (keys backup/...)
fass cp -r s3://dev-bucket/backup/ ./tree  # prefix download
fass cp s3://a/key s3://b/key              # S3→S3 (GET+PUT; no COPY endpoint in the SDK)
fass rm s3://dev-bucket/key
fass rm -r s3://dev-bucket/prefix/
fass mb new-bucket
fass rb new-bucket
fass presign s3://dev-bucket/key --ttl 15m
```

`cp` semantics:

* exactly one side may be local;
* a local directory (or a recursive prefix) requires `-r` / `--recursive`;
* a destination without a key (`s3://bucket`) or ending in `/` receives the
  file's basename;
* downloads verify the byte count against `HeadObject` and remove a truncated
  file instead of leaving a silently short object;
* `--content-type` overrides the MIME type inferred from the extension;
* `--json` prints one JSON array of `{source,dest,size,etag}`.

### 3.4 Admin commands (coordinator HTTP+JSON)

```bash
fass health                       # coordinator (and gateway, if --endpoint configured)
fass cluster status               # agents by state, per-nexus matrix, rings, RCs, ratio
fass node ls                      # nodes with agent counts
fass rc ls                        # RC parameters and storage overhead
fass repair status                # repair queue from /v1/repair/status (topology fallback)
fass gc status                    # deletion-GC counters from /metrics
```

All accept `--json`:

```bash
fass cluster status --json | jq '.agents.total, .agents.by_state.active'
# 12
# 12
fass rc ls --json | jq '.[0].params'
# {"geo_n":2,"geo_k":1,"local_n":3,"local_k":1}
```

What each reads:

| Command | Coordinator endpoint |
|---|---|
| `health` | `GET /healthz`, and the gateway's `GET /healthz` when an endpoint was explicitly configured |
| `cluster status` | `GET /v1/topology`, `GET /healthz` |
| `node ls` | `GET /v1/topology` |
| `rc ls` | `GET /v1/redundancy-classes` |
| `repair status` | `GET /v1/repair/status`: `queue.{pending,running,failed}` (pending and running disjoint), `oldest_pending_age_seconds`, `bytes_repaired_last_24h`, `throttled`, `per_site_budget_mbps`, `last_error`, `shardsets.{below_threshold,below_repair_watermark,unrecoverable}`. `null` means *unknown* and is rendered `unknown`/`-`, never `0`/`no`. A non-zero `shardsets.unrecoverable` prints a DATA LOSS warning. Falls back to a `/v1/topology`-derived risk summary on `404`/`405`/`501` or an empty response; real 5xx errors are surfaced. |
| `gc status` | `GET /metrics` (lines prefixed `fass_coordinator_gc_`) |

### 3.5 Output and exit codes

* Human output is an aligned text table.
* `--json` writes a single JSON document to stdout (no log noise); progress
  lines are suppressed.
* Exit codes: `0` success, `1` user error (bad arguments/URL, missing
  credentials, S3 4xx, unknown subcommand), `2` service error (connection
  refused, timeout, 5xx, unhealthy health target).

```bash
fass ls s3://dev-bucket/missing/ ; echo $?   # 1 (NoSuchKey)
fass cluster status --coordinator http://127.0.0.1:1 ; echo $?   # 2
```

---

## 4. `fass-console`

### 4.1 Run

```bash
export FASS_CONSOLE_PASSWORD='change-me'
./bin/fass-console \
  --listen=127.0.0.1:8081 \
  --coordinator=http://127.0.0.1:7000 \
  --console-user=admin \
  --console-password="$FASS_CONSOLE_PASSWORD" \
  --read-only=false          # omit / =true for read-only (the default)
```

Flags: `--listen`, `--coordinator`, `--console-user`, `--console-password`,
`--read-only` (default **true**), `--coordinator-timeout`, `--log-level`,
`--log-format`, `--version`.

The password is mandatory; the process refuses to start without one. Basic
auth is sent in clear text — terminate TLS in front of the console (or rely on
localhost/SSH tunnels) and never expose it directly to the Internet.

### 4.2 Routes

| Route | What it shows |
|---|---|
| `GET /` | Overview: coordinator health, agent states, capacity, rings, RC ratios, "needs attention", coordinator 5xx counter |
| `GET /buckets` | Buckets with config and object count/size (first 1,000 keys per bucket; `+` marks truncation) |
| `GET /buckets/{bucket}?prefix=&token=` | First page of objects, prefix filter, pagination |
| `GET /buckets/{bucket}/object?key=&version=` | HTMX fragment: manifest drawer (chunk table, coding, shard sets, encryption, retention) |
| `GET /agents` | Agents table: nexus/node/disk/state/last heartbeat/capacity/shards/actions |
| `GET /agents/{id}` | Agent detail: capacity, shard count, inventory digest, scrub cursor, scores |
| `POST /agents/{id}/activate` | Activate a **pending** agent (CSRF token required) |
| `POST /agents/{id}/decommission` | Start (or, with `on=false`, cancel) decommission (CSRF required) |
| `GET /partials/overview`, `/partials/agents` | HTMX auto-refresh fragments |
| `GET /static/*`, `GET /healthz` | Embedded assets; liveness (no auth) |

The table pages poll their fragment every 10–15 s via HTMX; the object drawer
loads on click.

### 4.3 Safety behaviour

* **Read-only by default.** With `--read-only` (default) the action buttons are
  not rendered and a direct POST returns `403 Read-only mode`.
* **CSRF.** Every write form carries a token from an `HttpOnly`,
  `SameSite=Strict` cookie; POSTs verify it in constant time. A mismatch is
  `403 CSRF check failed`.
* **Confirmation.** The browserside `data-confirm` prompt requires a second
  click for decommission.
* **No internals.** The console imports neither `internal/coord` nor
  `internal/gateway`; it consumes only the documented HTTP API, so it can run
  from an operator laptop against a remote coordinator.
* **Degraded mode.** If the coordinator is unreachable, every page still
  renders `200` with a red banner ("Coordinator unreachable or degraded") and
  empty data — it never crashes or returns a 500. The banner disappears on the
  next HTMX refresh once the coordinator is back.
* **Security headers.** `Content-Security-Policy: default-src 'self'`, `nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`. HTMX is embedded
  (no CDN) and `allowEval` is disabled.

### 4.4 Embedded assets, no Node

`internal/console/templates/*.html` and `internal/console/static/*` (CSS,
`app.js`, `htmx.min.js`) are compiled into the binary with `embed.FS`.
`make build` needs Go only. HTMX 1.9.12 is vendored (`htmx.LICENSE`, BSD
2-Clause); there is no CDN dependency, and `htmx.config.allowEval` is disabled
to keep the CSP strict.

### 4.5 Tests

```bash
source scripts/env.sh
go test ./cmd/fass-cli/ ./cmd/fass-console/ ./internal/console/   # unit + httptest
go test -race ./cmd/fass-cli/ ./internal/console/
make test                                                         # includes ./cmd/...
```

---

## 5. Verifying a deployment

```bash
source scripts/env.sh

# CLI
./bin/fass health
./bin/fass cluster status          # expect "Agents: 12 total, 12 ACTIVE, ..."
./bin/fass rc ls                   # dev-rc: geo 2+1, local 3+1, 2.00x
./bin/fass node ls

# 20 MiB round trip, byte-identical (the acceptance test used in this workstream)
head -c $((20*1024*1024)) /dev/urandom > /tmp/payload.bin
./bin/fass cp /tmp/payload.bin s3://dev-bucket/ops/payload.bin
./bin/fass cp s3://dev-bucket/ops/payload.bin /tmp/roundtrip.bin
cmp /tmp/payload.bin /tmp/roundtrip.bin && echo IDENTICAL
./bin/fass presign s3://dev-bucket/ops/payload.bin --ttl 5m | xargs curl -fsS -o /tmp/presigned.bin
cmp /tmp/payload.bin /tmp/presigned.bin && echo PRESIGN_OK

# Console
curl -fsS -u admin:change-me http://127.0.0.1:8081/healthz
curl -fsS -u admin:change-me http://127.0.0.1:8081/ | grep -c 'Cluster overview'
curl -fsS -u admin:change-me http://127.0.0.1:8081/agents | grep -c 'agents-body'
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8081/   # 401
```

For the console write actions, use the browser: the CLI intentionally has no
agent-activation command (writes from the console are CSRF-protected form
posts).

---

## 6. Known limitations

These are deliberate for the MVP; each is a candidate follow-up task.

**Auth / security**

* Single shared Basic credential (`--console-user`/`--console-password`). No
  per-user accounts, no sessions, no RBAC, no OIDC/SAML/Google/Microsoft
  login. Anyone with the password can perform the two write actions.
* No TLS in the console binary; only a `Secure` CSRF cookie is set under TLS.
  Put a TLS-terminating proxy in front of it.
* CSRF protection is double-submit-cookie only (appropriate for Basic auth
  without sessions; not a substitute for a real session layer).
* There is no audit log UI. Console writes are logged to the process log
  (`agent activated from console`, `agent decommission changed from console`)
  with the shared username.
* The coordinator's admin endpoints (`/v1/topology`, `/v1/agents/*`, `/metrics`)
  are unauthenticated by design (internal mTLS service in production); the CLI
  and console assume they run inside that trust boundary.

**Console data**

* Bucket object counts/sizes cover the first 1,000 keys per bucket and are
  labelled with `+` when truncated. A dedicated usage endpoint is future work.
* "Recent errors" is the coordinator's cumulative HTTP 5xx counter from
  `/metrics`; it is not a time-windowed error feed.
* No tenant/project/user/access-key pages, no RC/ring CRUD, no Smart Data
  Placement editor — read-only views only, matching the MVP scope.
* The console has no write action to create buckets or upload objects; use the
  CLI/S3 for data.

**CLI**

* Uploads are single PUTs. The payload is buffered to compute the SigV4
  payload hash, so peak memory is roughly the file size: comfortable for tens of
  MiB (the acceptance run used 20 MiB), but use `aws-cli`/`rclone` for
  multi-gigabyte objects — the documented single-PUT limit is 5 GiB and there is
  no CLI multipart upload yet.
* `ls`, recursive `cp` and `rm -r` page through **all** listings (S3 caps a page
  at 1,000 keys; the CLI follows continuation tokens to completion). A recursive
  copy or delete never stops at a page boundary.
* S3→S3 copies stream through the CLI (GET+PUT); the gateway's `CopyObject` is
  not exposed by the SDK yet.
* `repair status` consumes `GET /v1/repair/status` when the coordinator
  provides it (current release). It renders tri-state fields as `unknown` when
  the coordinator says `null` — "we don't know" must not look like "all good" —
  and prints a prominent `DATA LOSS` line when `shardsets.unrecoverable > 0`.
  Against an older coordinator it falls back to a topology-derived risk summary
  (offline/suspect agents, write-degraded nexuses, rings ≥ 80% full) and labels
  the source. `gc status` reports only counters exported on `/metrics`.

---

## 7. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `fass: missing S3 credentials` (exit 1) | no `--access-key`/`--secret`, env or profile | set them, or add a `~/.fass/config` profile |
| `SignatureDoesNotMatch` | wrong secret / region mismatch | check the profile; the region must match signing |
| `fass health`: gateway target FAIL | gateway not started or wrong `--endpoint` | `curl http://127.0.0.1:8080/healthz`; start the gateway |
| `fass cluster status`: connection refused (exit 2) | coordinator down/wrong URL | `curl http://127.0.0.1:7000/healthz`, check `--coordinator` |
| Console shows the red banner | coordinator unreachable | same as above; the UI recovers automatically |
| Console POST returns `403 CSRF check failed` | stale page or lost cookie | reload and retry; cookies must be enabled |
| Console POST returns `403 Read-only mode` | started with the default `--read-only` | restart with `--read-only=false` |
| Agent stuck `pending`, activate fails `409 AgentNotAnnounced` | agent never announced with its one-time secret | check the agent log; re-mint a secret via dev bootstrap only for non-ACTIVE agents |
| `fass ls`/`fass cp -r` is slow on huge prefixes | sequential listing is bounded by round trips | narrow the prefix or use `aws s3`/`rclone` for bulk migrations |

Logs: coordinator/agents/gateway/console log to stderr (`--log-format=json`
for structured output); the dev smoke script keeps them under `.dev/smoke-*`
(or your own redirects).
