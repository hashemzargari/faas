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

Two paths with the same topology (3 Nexuses, 12 per-disk agents):

* **containers**: `make dev` (below) — builds the image, boots the stack, runs
  the S3 round-trip smoke check and tears everything down;
* **processes on the host**: `scripts/smoke-cluster.sh` (no Docker), with the
  step-by-step recipe further down.

### 2.1 Docker compose (containers, fastest)

```bash
make dev          # build image -> up -> smoke check -> down -v
make dev-up       # boot and leave it running
make dev-logs     # follow logs
make dev-down     # tear down, including volumes
```

`make dev` requires Docker Engine + Compose v2 and, on the first run, builds
`deploy/docker/Dockerfile` as `fass:dev` (a few minutes; the image is
distroless, so health probes use the small embedded `fass-dev-healthcheck`).

What the stack does (`deploy/docker/compose.dev.yml`):

1. `init-volumes` chowns the named volumes to uid 65532 (the image's nonroot
   user), so no FASS process runs as root. The coordinator, gateway and agents
   run with their explicit dev plaintext switches (`FASS_COORDINATOR_DEV`,
   `FASS_GATEWAY_DEV`, `FASS_AGENT_INSECURE`) because all three now fail closed
   outside dev; `/healthz` reports `security.insecure=true`.
2. `coordinator` starts with `--dev-bootstrap`: it creates/reconciles the
   deterministic topology (3 Nexuses, 6 nodes, 12 disks, RC `dev-rc`
   `geo 2+1 / local 3+1`, bucket `dev-bucket`) and writes
   `dev-bootstrap.json` into its data volume. Bootstrap is idempotent.
3. `bootstrap` (one-shot) reads that JSON and writes one announce-secret file
   per agent under `/secrets`; the agents wait for it
   (`service_completed_successfully`) and consume it via
   `FASS_AGENT_SECRET_FILE`, so **no secret is baked into the compose file or
   put in argv**.
4. `gateway` starts with a deterministic dev key seed
   (`FASS_DEV_KEY_SEED`, overridable) so objects remain readable across
   restarts — never the ephemeral seed.
5. `smoke` (run explicitly by `make dev`) waits for the 12 agents to announce,
   activates them through the coordinator API, and performs a real SigV4
   `PUT/HEAD/GET/DELETE` of 1 MiB to `s3://dev-bucket/dev/smoke.bin`,
   comparing bytes. It prints `SMOKE OK: 12 agents ACTIVE…`.

Dev credentials: `dev-access-key` / `dev-secret-key`, region `eu-west-1`;
the gateway is published on `127.0.0.1:8080`, the coordinator (admin API) on
`127.0.0.1:7000`. From the host you can use the CLI against it:

```bash
FASS_ENDPOINT=http://127.0.0.1:8080 FASS_ACCESS_KEY_ID=dev-access-key \
FASS_SECRET_ACCESS_KEY=dev-secret-key ./bin/fass cluster status
```

Re-running against a *kept* data volume is refused by design: the coordinator
only mints announce secrets for non-ACTIVE agents, and an agent needs a fresh
secret to announce. `make dev` always tears the volumes down; if you use
`make dev-up`, reset with `make dev-down` before the next boot.

This is a single-host simulation of three sites — convenient, not a production
topology. For sizing, upgrade and rollback of a real install, see
[docs/09-deployment.md](09-deployment.md).

### 2.2 Prerequisites

```bash
cd /path/to/fass
source scripts/env.sh          # workspace-local GOPATH/GOCACHE, -mod=vendor
make build test                # builds bin/, runs unit tests
```

The sandbox (and the repo) never needs network: dependencies are vendored.

### 2.3 Processes on the host: one command (smoke)

```bash
./scripts/smoke-cluster.sh              # upload + read
./scripts/smoke-cluster.sh --nexus-loss # kill a whole Nexus, then read
```

This boots a real coordinator + 12 agents + gateway, uploads 14 MiB and reads it
back; `--nexus-loss` SIGKILLs every `nexus-c` agent first and proves the read
still succeeds through `geo_n = 2`.

### 2.4 Processes on the host: step by step (what the script does, for debugging)

```bash
source scripts/env.sh
make build

# 1. Coordinator with the deterministic dev topology. It prints one line:
#    FASS_DEV_BOOTSTRAP {"access_key_id":"dev-access-key",...,"agents":[12]...}
#    and writes the same JSON to <data-dir>/dev-bootstrap.json.
#    --dev is the explicit plaintext switch (`--dev-bootstrap` implies it). A
#    coordinator outside dev fails closed without --tls-cert/--tls-key, so any
#    copy of this recipe that drops --dev must also add TLS material.
./bin/fass-coordinator --listen=127.0.0.1:7000 --dev \
  --data-dir=.dev/coord --dev-bootstrap >.dev/coord.log 2>&1 &
grep -o 'FASS_DEV_BOOTSTRAP .*' .dev/coord.log | cut -d' ' -f2- >.dev/boot.json

# 2. One agent per disk (12 total: 6 nodes × 2 disks, 2 nodes per Nexus).
#    --secret is the one-time announce secret from boot.json; --disk-id is the
#    operator-facing slot label ("disk-a1-1"), not the agent identity.
#    --insecure is the explicit dev-only plaintext switch: agents fail closed
#    without TLS material otherwise (docs/08 §4).
python3 - <<'PY' >.dev/agents.sh
import json
d = json.load(open(".dev/boot.json"))
for i, a in enumerate(d["agents"]):
    print(f'./bin/fass-agent --nexus-id={a["nexus_id"]} --node-id={a["node_id"]} '
          f'--disk=.dev/disks/a{i} --port={7100+i} --coordinator-url=http://127.0.0.1:7000 '
          f'--secret={a["secret"]} --disk-id={a["disk_id"]} --insecure --repair=false --scrub=false &')
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
  --coordinator=http://127.0.0.1:7000 --insecure \
  --console-user=admin --console-password=change-me \
  --read-only=false >.dev/console.log 2>&1 &
```

Dev credentials are `dev-access-key` / `dev-secret-key`, region `eu-west-1`,
bucket `dev-bucket`, RC `dev-rc`, ring `dev-ring`.

Stop everything with `kill` on the PIDs (the smoke script does it in a `trap`).
The coordinator's SQLite store lives in `--data-dir`; delete it for a clean
slate.

### 2.5 Agent configuration: environment variables and secret files

`fass-agent` accepts every flag from a `FASS_AGENT_*` environment variable as
well as from argv. Precedence is always **explicit flag > environment variable >
default**, so a flag can override a bad environment file while debugging.

The environment variable name is the flag name upper-cased with `-` replaced by
`_`: `--coordinator-url` → `FASS_AGENT_COORDINATOR_URL`,
`--max-shard-bytes` → `FASS_AGENT_MAX_SHARD_BYTES`. Every flag except
`--version` (an action, not configuration) has an environment variable; a new
flag gets one automatically. `fass-agent --help` documents this.

An agent can therefore be configured with no argv at all:

```bash
FASS_AGENT_DISK=/var/lib/fass/disk1 \
FASS_AGENT_PORT=7100 \
FASS_AGENT_NEXUS_ID=nexus-a \
FASS_AGENT_NODE_ID=node-a1 \
FASS_AGENT_DISK_ID=disk-a1 \
FASS_AGENT_COORDINATOR_URL=https://coordinator.internal:7000 \
FASS_AGENT_SECRET_FILE=/etc/fass/agents/a1.secret \
./bin/fass-agent
```

**The announce secret must not go in argv.** Command-line arguments are visible
to every local user via `ps`, so production deployments should use
`--secret-file` / `FASS_AGENT_SECRET_FILE` (or `FASS_AGENT_SECRET` injected from
a systemd `EnvironmentFile` or a Kubernetes Secret). `--secret` still works for
local debugging and logs a warning on every start when used.

`--secret-file` reads exactly one line and trims **one** trailing newline
(CRLF included). An empty or whitespace-only file, and a multi-line file, are configuration
errors — an empty secret file is never treated as "no secret / dev mode". Setting both `--secret` (or `FASS_AGENT_SECRET`) and
`--secret-file` (or `FASS_AGENT_SECRET_FILE`) fails closed with an error naming
both sources, because silently preferring one could join the wrong cluster.

```bash
# one agent per disk under systemd (see deploy/systemd/fass-agent@.service):
# /etc/fass/agents/disk-a1.env contains FASS_AGENT_SECRET_FILE=/etc/fass/agents/disk-a1.secret
install -m 0600 announce.secret /etc/fass/agents/disk-a1.secret
FASS_AGENT_DISK=/data/disk-a1 FASS_AGENT_SECRET_FILE=/etc/fass/agents/disk-a1.secret \
  ./bin/fass-agent --nexus-id=nexus-a --node-id=node-a1 --disk-id=disk-a1
```

The same file-based pattern is used for credentials generally, and will apply
to the TLS material (`--tls-cert`, `--tls-key`, `--tls-ca`) when transport
encryption lands: paths, never secret content, on the command line.

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
# Dev/plaintext coordinator: the opt-in is explicit and shows in the banner.
./bin/fass-console \
  --listen=127.0.0.1:8081 \
  --coordinator=http://127.0.0.1:7000 --insecure \
  --console-user=admin \
  --console-password="$FASS_CONSOLE_PASSWORD" \
  --read-only=false          # omit / =true for read-only (the default)

# Production shape: HTTPS listener + TLS-only coordinator + mTLS client identity.
./bin/fass-console \
  --listen=0.0.0.0:8443 \
  --tls-cert=/etc/fass/tls/console/tls.crt --tls-key=/etc/fass/tls/console/tls.key \
  --coordinator=https://coordinator.example.internal:7000 \
  --coordinator-ca=/etc/fass/tls/ca/ca.crt \
  --coordinator-client-cert=/etc/fass/tls/console-client/tls.crt \
  --coordinator-client-key=/etc/fass/tls/console-client/tls.key \
  --console-user=admin --console-password="$FASS_CONSOLE_PASSWORD"
```

Flags: `--listen`, `--coordinator`, `--console-user`, `--console-password`,
`--read-only` (default **true**), `--coordinator-timeout`, `--log-level`,
`--log-format`, `--version`.

TLS flags: `--tls-cert/--tls-key` serve the console over HTTPS; optional
`--tls-client-ca` + `--require-mtls` demand operator client certificates
(browser UX is poor — prefer a proxy/SSO for humans). `--coordinator-ca` is
**required** for an `https://` coordinator; `--coordinator-client-cert/-key` are
presented to a `--require-mtls` coordinator; `--coordinator-server-name`
overrides the verified name. Plaintext is **all-or-nothing**: an `http://`
coordinator requires the explicit `--insecure` (or `--dev`) opt-out — there is
no per-hop insecure flag. Either plaintext choice is reported in `/healthz`
(`"security":{"insecure":true,...}`) and as a persistent banner.

**Removed in this release:** the per-hop `--coordinator-insecure` flag (and
`FASS_CONSOLE_COORDINATOR_INSECURE`) is gone from the documented interface. It
is still accepted for one release as a deprecated alias that logs a warning and
maps to `--insecure`, so existing scripts fail loudly instead of mysteriously;
switch them to `--insecure`/`--dev`. The gateway's plaintext transition flag is
likewise gone: plaintext is all-or-nothing through `--dev`/`--insecure`.

The password is mandatory; the process refuses to start without one. When the
console listener is plaintext, Basic auth is sent in clear text — terminate TLS
in front of it (or rely on localhost/SSH tunnels) and never expose it directly to
the Internet. A wrong coordinator CA makes startup fail with an actionable
`coordinator TLS verification failed` error instead of a running console that
returns 500s.

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
| `make dev`: buildx complains it cannot write its state (`read-only file system`, sandboxed/CI HOME) | Docker CLI keeps buildx state under `$HOME/.docker` | point it at a writable dir: `DOCKER_CONFIG=$PWD/.dev/docker-config make dev` |
| A component exits with `refusing to start ... TLS` / `TLS is required` | the TLS rollout made non-dev startup fail closed; plaintext needs an explicit opt-in | dev: `--dev` (coordinator/gateway) or `--insecure` (agent); production: provide `--tls-cert/--tls-key` (+ CA/mTLS) |

Logs: coordinator/agents/gateway/console log to stderr (`--log-format=json`
for structured output); the dev smoke script keeps them under `.dev/smoke-*`
(or your own redirects).

---

## 4. TLS / mTLS (data plane, control plane, rotation)

Every hop ships with TLS available and **fails closed outside dev**: the gateway and
agents refuse to start without TLS material unless you pass `--insecure` (or run
`--dev`). Plaintext is always loud: a warning is printed on **every** start and
`/healthz` carries a machine-readable `security` block, so a "temporarily
plaintext" deployment cannot hide.

```console
$ curl -s localhost:9000/healthz | jq .security
{
  "insecure": true,
  "agent_mode": "off",
  "require_mtls": false,
  "s3_tls": false
}
```

`agent_mode` is `require` (TLS only), `auto` (TLS with a logged per-endpoint
plaintext fallback during a mixed-mode rollout) or `off` (plaintext, only with
`--insecure`/`--dev`).

### 4.1 Three-step runbook: init CA → issue certs → enable strict

TLS 1.3 only (`crypto/tls`, `crypto/x509`; no external dependencies). The CA key
is written `0600` and is **never required at runtime** by any component.

```console
# 1. Create the cluster CA (keep ca.key offline; only ca.crt is distributed).
fass pki init --dir /etc/fass/pki/ca --cn fass-cluster-ca

# 2. Issue certificates (one per listener identity; SANs must match how peers dial it).
#    Gateway S3/control client + agent shard listeners:
fass pki issue-server --ca-dir /etc/fass/pki/ca --dir /etc/fass/pki/agent \
  --dns agent-a1.internal --ip 10.0.0.11 --ttl 2160h
fass pki issue-client --ca-dir /etc/fass/pki/ca --dir /etc/fass/pki/gateway \
  --identity gateway-1 --ttl 2160h
#    (The same commands remain available as `fass-gateway pki ...` for
#    compatibility; the neutral CLI is the documented form.)
#    Inspect any certificate (expiry, SANs, fingerprint):
fass pki inspect --cert /etc/fass/pki/agent/tls.crt

# 3. Enable TLS, then strict mTLS once every peer presents a certificate.
#    The coordinator is fail-closed outside --dev: it needs its own certificate.
#    --require-mtls additionally verifies client certificates against --tls-client-ca.
fass-coordinator --tls-cert /etc/fass/pki/coordinator/tls.crt \
                 --tls-key /etc/fass/pki/coordinator/tls.key \
                 --tls-client-ca /etc/fass/pki/ca/ca.crt --require-mtls
fass-agent --tls-cert /etc/fass/pki/agent/tls.crt --tls-key /etc/fass/pki/agent/tls.key \
           --tls-ca /etc/fass/pki/ca/ca.crt --require-mtls
fass-gateway --ca-cert /etc/fass/pki/ca/ca.crt \
             --client-cert /etc/fass/pki/gateway/tls.crt --client-key /etc/fass/pki/gateway/tls.key \
             --agent-tls require --require-mtls \
             --coordinator https://coordinator.internal:7001 --coordinator-ca /etc/fass/pki/ca/ca.crt
```

| Gateway flag | Env | Meaning |
|---|---|---|
| `--ca-cert` | `FASS_GATEWAY_CA_CERT` | CA bundle used to verify agents and the coordinator |
| `--client-cert` / `--client-key` | `FASS_GATEWAY_CLIENT_CERT` / `FASS_GATEWAY_CLIENT_KEY` | gateway identity for mTLS |
| `--agent-tls off\|auto\|require` | `FASS_GATEWAY_AGENT_TLS` | data-plane mode (default `require`) |
| `--require-mtls` | `FASS_GATEWAY_REQUIRE_MTLS` | strict: no plaintext peers, client certs mandatory |
| `--coordinator-ca` | `FASS_GATEWAY_COORDINATOR_CA` | CA bundle for the coordinator (defaults to `--ca-cert`) |
| `--insecure` | `FASS_GATEWAY_INSECURE` | explicit plaintext; warning on every start, visible in `/healthz` |
| `--tls-cert` / `--tls-key` | `FASS_GATEWAY_TLS_CERT` / `FASS_GATEWAY_TLS_KEY` | serve the S3 edge over HTTPS |

Non-dev gateways refuse to start with `--ca-cert` missing, `--agent-tls=off`
(without `--insecure`), `--require-mtls` without a client certificate, or a
plaintext `--coordinator` URL.

> **Control plane is TLS end to end.** The coordinator listener takes
> `--tls-cert/--tls-key` and `--tls-client-ca --require-mtls`; the gateway dials
> it with `--coordinator https://… --coordinator-ca` and fails closed otherwise;
> agents dial it with `--coordinator-ca` plus
> `--coordinator-client-cert/--coordinator-client-key` (see the agent table
> below). There is no "plaintext control plane" flag. The only exception is an
> explicitly labelled dev cluster: `--dev` with an `http://` coordinator is
> permitted, warns on every start, and reports `security.coordinator_tls:false`
> in `/healthz` — never use it outside local development.

**Agent listener flags.** Agents follow the same fail-closed rule: TLS is
required unless `--insecure` is passed explicitly.

| Agent flag | Env | Meaning |
|---|---|---|
| `--tls-cert` / `--tls-key` | `FASS_AGENT_TLS_CERT` / `FASS_AGENT_TLS_KEY` | shard listener certificate/key (required unless `--insecure`) |
| `--tls-ca` | `FASS_AGENT_TLS_CA` | CA bundle used to verify gateway client certs on the listener **and** peer certificates for repair |
| `--tls-client-cert` / `--tls-client-key` | `FASS_AGENT_TLS_CLIENT_CERT` / `FASS_AGENT_TLS_CLIENT_KEY` | optional repair-client identity; defaults to `--tls-cert`/`--tls-key`, which must then carry the client-auth EKU (`pki.UsageBoth` or `IssueClient`) |
| `--require-mtls` | `FASS_AGENT_REQUIRE_MTLS` | require and verify client certificates on the listener (needs `--tls-ca`) |
| `--insecure` | `FASS_AGENT_INSECURE` | explicit plaintext, dev only; warns on every start |

Agent TLS notes:
* An agent with TLS enabled is TLS-*only* on the shard listener even without
  `--require-mtls`: the listener no longer speaks plaintext, and client
  certificates are verified when presented (mixed-mode rollout). Plaintext
  agents are the ones started with `--insecure`, and the gateway sees those as
  plaintext endpoints.
* `--require-mtls` needs `--tls-ca`; a repair-enabled agent also needs
  `--tls-ca`, because agent-to-agent shard fetches verify peer certificates
  instead of silently downgrading to plaintext.
* `/v1/healthz` reports the agent posture as `{"tls":false,"insecure":true}`
  (plaintext) or `{"tls":true,"insecure":false,"tls_not_after":"..."}`; the
  richer `/v1/stats` block is
  `tls:{enabled,mutual,insecure,not_after,renewal_due,issuer,subject}` and every
  heartbeat carries `tls_enabled`, `insecure` and `cert_not_after`, so
  `fass cluster status` can answer "is any agent plaintext?" and "which
  certificates expire soon?" without polling each agent.
* Certificate rotation needs no agent restart (see §4.2): the listener reloads
  `--tls-cert`/`--tls-key` on the next handshake once the served certificate is
  inside its renewal window, and a half-written key file during rotation keeps
  the previous certificate serving.

**Agent → coordinator TLS (control plane).** Configured separately from the
shard listener: it is normal for the coordinator to sit behind a different CA
than the agent mesh, so the flags are deliberately distinct.

| Agent flag | Env | Meaning |
|---|---|---|
| `--coordinator-ca` | `FASS_AGENT_COORDINATOR_CA` | CA bundle that verifies the coordinator's server certificate; **required** for an `https://` coordinator URL |
| `--coordinator-server-name` | `FASS_AGENT_COORDINATOR_SERVER_NAME` | name verified against the coordinator certificate (default: host from `--coordinator-url`) |
| `--coordinator-client-cert` / `--coordinator-client-key` | `FASS_AGENT_COORDINATOR_CLIENT_CERT` / `FASS_AGENT_COORDINATOR_CLIENT_KEY` | agent identity presented to a coordinator running `--require-mtls` |

Fail-closed rules (checked at startup, before any announce):

* `https://` coordinator URL **without** `--coordinator-ca` → refuse to start.
  An `https://` URL is never downgraded to plaintext.
* `http://` coordinator URL (or a legacy `host:port` value) **without**
  `--insecure` → refuse to start.
* `--insecure` together with any `--coordinator-*` TLS flag → refuse to start
  (ambiguous configuration).
* `--coordinator-client-cert`/`--coordinator-client-key` must carry the
  client-auth EKU; a server-only certificate is rejected at startup with an
  actionable message. When neither flag is set, the agent falls back to the
  repair identity (`--tls-client-cert/--tls-client-key`), then to a
  both-usage listener identity, and otherwise connects server-auth-only.
* If the coordinator is switched to `--require-mtls` and an agent has no client
  certificate, announce fails with an error naming
  `--coordinator-client-cert/--coordinator-client-key` — not an opaque
  handshake failure.

**SAN guidance for the coordinator certificate.** Agents (and gateways) verify
the certificate against the host in the URL, and deployments announce
`hostname:port`, so the coordinator certificate needs a **DNS SAN for the
hostname peers dial** (for example `coordinator.internal`), not just an IP SAN.
If the dialed address is a load balancer / VIP that is not in the SAN list, set
`--coordinator-server-name` to a name that *is* in the certificate. Keep the
coordinator's own certificate rotation on the same `pki` renewal window as the
rest of the cluster.

```console
# coordinator (mutual TLS, verifies agent/gateway client certs)
fass-coordinator --listen :7000 --tls-cert /etc/fass/pki/coordinator/tls.crt \
  --tls-key /etc/fass/pki/coordinator/tls.key \
  --tls-client-ca /etc/fass/pki/ca/ca.crt --require-mtls

# agent: encrypted control plane, explicit agent identity for coordinator mTLS
fass-agent --disk /data --coordinator-url https://coordinator.internal:7000 \
  --coordinator-ca /etc/fass/pki/ca/ca.crt \
  --coordinator-client-cert /etc/fass/pki/agent/tls.crt \
  --coordinator-client-key /etc/fass/pki/agent/tls.key
```

The control-plane TLS posture is logged at startup
(`coordinator control-plane TLS enabled`, including the verified server name)
and is independent of `/v1/healthz`'s shard-listener `tls`/`insecure` fields.

### 4.2 Rotation without a flag day

Certificates renew inside a window of **one third of their lifetime, capped at
24 h** (`pki.RenewalWindow`; a 90-day cert renews 30 days early). Agents reload
cert/key from disk on the next handshake once inside the window, keeping existing
connections alive — no coordinated restart of twelve agents.

```console
# Issue the replacement to the same paths the component reads (atomic replace),
fass pki issue-server --ca-dir /etc/fass/pki/ca --dir /etc/fass/pki/agent.new ...
# then move tls.crt/tls.key into place for the component; in-flight connections finish
# on the old certificate, the next handshake picks up the new one.
```

`fass cluster status` warns when a component is inside its renewal window
(`/v1/stats` exposes `tls.not_after`).

### 4.3 Mixed-mode rollout (upgrading live agents)

1. Roll out TLS listeners with `--insecure` still present on the not-yet-updated agents.
2. Run gateways with `--agent-tls auto --ca-cert ...`: TLS peers are verified,
   plaintext peers are used with a warning per endpoint. `/healthz` stays
   `insecure=false` but the warnings make the remaining plaintext list visible.
3. When every agent has TLS, flip gateways to `--agent-tls require --require-mtls`.
   From then on a plaintext agent is a hard failure, not a quiet downgrade.

The transition is a state, not an option: compat/tests assert that strict mode
rejects a plaintext peer, and an expired certificate fails with an actionable
`renew/re-enroll` message rather than an opaque handshake error.

### 4.4 Verifying the shipped matrix in both modes

```console
make compat-clients              # 16 checks, plaintext data plane, HTTP edge
make compat-clients-tls          # mTLS data plane, HTTP edge
make compat-clients-control-tls  # + mTLS control plane (coordinator+agents+gateway)
make compat-clients-full-tls     # every hop TLS: data + control + HTTPS S3 edge
```

Each mode mints a throwaway CA under the run's temp directory with
`fass pki`; nothing is written to the repository.

| Mode | Environment | What is encrypted |
|---|---|---|
| plaintext | (none) | nothing — dev cluster, `--insecure` everywhere, warned and visible |
| data plane | `COMPAT_TLS=1` | agent shard transport mTLS (12 agents `--require-mtls`, gateway `--agent-tls=require --require-mtls`) |
| control plane | `COMPAT_CONTROL_TLS=1` | + coordinator listener mTLS, agents `--coordinator-ca`/client certs, gateway `https://` + `--coordinator-ca`; implies `COMPAT_TLS=1` |
| edge | `COMPAT_EDGE_TLS=1` | + S3 edge HTTPS (`--tls-cert/--tls-key` from the same CA) |
| end state | `COMPAT_CONTROL_TLS=1 COMPAT_EDGE_TLS=1` | **every hop**: shard, control, S3 edge (repair uses the same CA/identity) |

The script asserts each `/healthz` posture it claims: gateway
`security.{insecure,agent_mode,require_mtls,s3_tls,coordinator_tls,…}`,
coordinator `{tls,mtls,insecure}`, agents `{tls,insecure,tls_not_after}`. A
matrix that passes with a mislabelled posture fails here.

The edge certificate must have a SAN for the host clients dial
(`--ip 127.0.0.1` and `--dns "$(hostname)"` — the script does both); SNI uses
that endpoint host. Each client is pointed at the custom CA with its own
mechanism, which is the friction worth knowing:

| Client | Custom CA | Gotcha |
|---|---|---|
| aws-cli v1 | `AWS_CA_BUNDLE=/path/ca.crt` (env) | v1's `--ca-bundle` parsing is unreliable across subcommands; the env var is the dependable path |
| rclone | global `--ca-cert /path/ca.crt` on every invocation | no per-remote `ca_cert` for the `s3` backend, so it must be in the rclone wrapper/config flags |
| s3cmd | `ca_certs_file = /path/ca.crt` + `use_https = True` + `check_ssl_certificate = True` in `.s3cfg` | a stale `use_https = False` silently downgrades the client, so verify it in the generated config |

The script's success line reports exactly which hops were encrypted, e.g.
`COMPAT: PASS (data plane mTLS; control plane mTLS; S3 edge HTTPS (custom CA))`.
A mode that has never been executed is not coverage; all four are run as part of
the release check.
Nothing is written to the repository and the temp directory is removed on
success (`COMPAT_KEEP=1` keeps the logs).
