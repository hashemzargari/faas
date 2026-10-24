# 09 — Deployment: Kubernetes (Helm), systemd VMs, and 3-site operations

This is the operational story for running FASS outside a laptop: what to
deploy, how to size it from the Redundancy Class, the upgrade order and why,
what is unsafe, and how to check the cluster on day 2.

Artifacts:

| Artifact | Path |
|---|---|
| Helm chart | [`deploy/helm/fass`](../deploy/helm/fass) ([README](../deploy/helm/fass/README.md)) |
| Example values (dev / single-site / three-site) | `deploy/helm/fass/values-*.yaml` |
| systemd units + env examples | [`deploy/systemd`](../deploy/systemd) ([README](../deploy/systemd/README.md)) |
| Lint gate | `make deploy-lint` (skips cleanly when `helm`/`systemd-analyze` are absent) |

For a laptop/dev cluster, [docs/08-operations.md](08-operations.md) is the
short path (`scripts/smoke-cluster.sh`).

> **Production readiness.** The storage engine is real and tested, but several
> pieces of the *operations* surface that a multi-site install wants are not
> implemented yet — most importantly a PostgreSQL-backed coordinator, TLS/mTLS
> on the coordinator, KMIP key custody, and environment/secret-file
> configuration for the agent. They are listed with workarounds in
> [§Known product gaps](#known-product-gaps). Deploy with those constraints in
> mind rather than assuming them away.

---

## 1. Components, ports, trust boundaries

| Component | Process | Default port(s) | State | Replicas |
|---|---|---|---|---|
| Coordinator | `fass-coordinator` | 7000 | metadata: PostgreSQL (production) or embedded store (dev/small) | 1 with embedded, ≥1 with PostgreSQL |
| Gateway | `fass-gateway` | 8080 (S3), 9000 (admin: `/healthz`, `/readyz`, `/metrics`) | stateless | ≥2 per site |
| Console | `fass-console` | 8081 | stateless | 1 |
| Agent | `fass-agent` | 7100+ (one per disk) | one disk (shards + `state.json`) | one per disk |

Trust boundaries:

* **Clients → gateway**: internet/DMZ. TLS terminated by the gateway
  (`--tls-cert/--tls-key`) or by an L4 LB.
* **Gateway → coordinator**: control plane (JSON). No TLS in this release: use a
  private network, VPN or service mesh; never expose port 7000 publicly.
* **Gateway → agents**: shard traffic on 7100+ (plain HTTP today). Agents also
  need *inbound* from every gateway, so this must be a routed storage network.
* **Agent → coordinator**: announce/heartbeat/repair (outbound).
* **Console → coordinator**: read-mostly JSON; console has no TLS and a single
  Basic credential — bind it to loopback/private and front it with your TLS
  reverse proxy + SSO.

The coordinator admin API (`/v1/topology`, `/v1/agents*`, `/v1/rings`,
`/v1/redundancy-classes`, `/metrics`) is **unauthenticated** by design in v1
(an internal mTLS service in the target architecture). Keep it on the private
network.

---

## 2. Deployment shapes

### 2.1 One Kubernetes cluster spanning the three sites (simplest)

All nodes are in one cluster (L3 connectivity between sites), nodes are labelled
per site, and the chart renders all components plus one pinned agent Deployment
per node.

```bash
kubectl label node node-a1 fass.io/nexus=nexus-a
...
helm install fass ./deploy/helm/fass -n fass --create-namespace \
  -f deploy/helm/fass/values-three-site.yaml
```

Use this when cross-site latency and a shared control plane are acceptable.
Gateways can be pinned per site with `gateway.nodeSelector` (one release) or
split into per-site releases (below).

### 2.2 One release per site, control plane in site A (recommended for true sites)

Each site is its own Kubernetes cluster. Site A runs the coordinator; every site
runs gateways and agents; the console can live in an operations cluster.

```yaml
# site A (control + local data plane)
coordinator:
  enabled: true
gateway:
  enabled: true
console:
  enabled: true
agents:
  enabled: true
  coordinatorURL: http://coordinator.site-a.internal:7000   # agents announce here
```

```yaml
# site B / site C (data plane only)
coordinator:
  enabled: false
gateway:
  enabled: true
  coordinatorURL: http://coordinator.site-a.internal:7000
console:
  enabled: false
agents:
  enabled: true
  coordinatorURL: http://coordinator.site-a.internal:7000
```

Constraints:

* every site's nodes must be registered with the coordinator as `Node`s and the
  agent `--node-id` must equal the Kubernetes node name (the chart sets this);
* the coordinator's **Node** ids must also match across releases — create them
  with the bootstrap API in §3.3;
* cross-site coordinator traffic needs a VPN/private link (no coordinator TLS
  yet);
* the site-A coordinator is a single point of control (not of data: reads/writes
  continue through gateway caches briefly, but placements/commits need it).

### 2.3 VMs / bare metal with systemd

Use [deploy/systemd](../deploy/systemd/README.md): one unit per disk
(`fass-agent@disk0`), one gateway per site (or two behind an LB), one
coordinator in site A, console on loopback behind a proxy. The sizing in §3
applies identically.

---

## 3. Sizing from the Redundancy Class

### 3.1 The parameters and the ratio

An RC is the tuple `geo(n,k) × local(n,k)`, plus `aag` and `chunk_size`
(immutable once created — see §6).

```
total shards per chunk  = (geo_n + geo_k) × (local_n + local_k)
data shards per chunk   = geo_n × local_n
ratio                   = ((geo_n+geo_k)/geo_n) × ((local_n+local_k)/local_n)
usable capacity         = raw capacity / ratio          (before reserves, below)
shards per Nexus/chunk  s = local_n + local_k
```

Ratio table (from [docs/02 §6.2](02-architecture.md); "usable per 1 PB raw" is
capacity only — apply the reserves below):

| Profile | geo | local | aag | Ratio | Usable per 1 PB raw | Tolerates |
|---|---|---|---|---|---|---|
| Single-site economical | 1+0 | 8+2 | 2 | 1.25× | 800 TB | 2 disks / 1 server |
| Single-site standard | 1+0 | 16+4 | 2 | 1.25× | 800 TB | 4 disks / 2 servers |
| **3-site geo (recommended)** | 2+1 | 16+4 | 2 | **1.875×** | 533 TB | 1 site + 2 servers/site |
| 3-site geo-resilient | 3+2 | 4+2 | 1 | 2.5× | 400 TB | 2 sites + 2 servers/site |
| Edge / 2-site | 2+1 | 6+3 | 2 | 2.25× | 444 TB | 1 site + 3 disks/site |
| Cubbit DS3-Cloud flat | 1+0 | 20+40 | 1 | 3.0× | 333 TB | 40 of 60 nodes |

### 3.2 AAG is a per-Node rule — and what it means for topology

The coordinator's placement hard constraint ([docs/03 §4.2](03-data-plane.md#42-hard-constraints-filters--a-candidate-failing-any-is-dropped))
is: **at most `aag` shards of the same shard-set per Node**. Each Nexus must
hold `s = local_n + local_k` shards of every chunk, each on a distinct agent
(one shard per agent per set). Therefore, for every Nexus:

```
agents per Nexus        ≥ s                      (distinct agents for one chunk)
nodes per Nexus         ≥ ceil(s / aag)          (per-Node shard cap)
disks per node          ≤ aag  (chart default; see note)
```

This is why "3 nodes × 12 disks" is **not** a valid layout for `local 16+4,
aag 2`: 12 disks per node does not help one shard-set, which may use at most 2
shards on that node, so 3 nodes can hold at most 6 of the 20 shards. The
recommended shape is **10 nodes × 2 disks per Nexus** (20 agents) — the same
number of nodes Cubbit's published `10 servers × 8 disks` example uses.

Note on disks per node: technically a node may hold *more* disks than `aag`;
the extra disks serve *other* shard-sets and are not wasted. But the per-node
blast radius and the capacity arithmetic change in ways operators routinely get
wrong, so the chart refuses `disks > aag` unless
`agents.allowAgentsPerNodeExceedingAAG=true` is set deliberately.

Minimum viable Nexus per RC (aag=2, 2 disks/node):

| RC | s | min nodes/Nexus | min agents/Nexus |
|---|---|---|---|
| `2+1 × 16+4` | 20 | 10 | 20 |
| `2+1 × 6+3` | 9 | 5 | 9 |
| `1+0 × 16+4` | 20 | 10 | 20 |
| `3+2 × 4+2` (aag=1) | 6 | 6 | 6 |

### 3.3 Capacity arithmetic (with the two reserves)

Provision for **both** the ring watermark and the agent's disk reserve:

```
raw_required            = usable_target × ratio
disk_raw_provisioned    ≥ raw_required / (0.85 × 0.95)        ← ring 85% × agent 5%
disk_raw_per_Nexus      = disk_raw_provisioned / (geo_n + geo_k)
disks_per_Nexus         = ceil(disk_raw_per_Nexus / disk_size)
nodes_per_Nexus         = ceil(disks_per_Nexus / disks_per_node)
```

The ring stops accepting placements at **85%** occupancy ([docs/03 §4.6](03-data-plane.md));
each agent reserves **5%** of its filesystem (`--reserve-pct`, default 5) so a
disk can never fill. Both are already enforced in code, so leaving either out of
the sizing means you buy storage the cluster refuses to use.

**Worked example — recommended RC (`2+1 × 16+4`, aag 2), 18 TiB disks,
2 disks/node:**

```
s = 20, min nodes/Nexus = ceil(20/2) = 10, agents/Nexus = 20
disk raw/Nexus    = 20 × 18 TiB                 = 360 TiB
cluster raw       = 3 × 360                     = 1080 TiB
after 5% reserve  = 1080 × 0.95                 = 1026 TiB
after 85% ring    = 1026 × 0.85                 = 872.1 TiB
usable            = 872.1 / 1.875               = 465.1 TiB
layout            = 3 Nexuses × 10 nodes × 2 disks = 60 agents
```

**Worked example — target 1 PiB usable (same RC, 18 TiB disks, 2 disks/node):**

```
raw_required      = 1024 × 1.875                 = 1920 TiB
provision         = 1920 / (0.85 × 0.95)         = 2377.7 TiB
per Nexus         = 2377.7 / 3                   = 792.6 TiB
disks/Nexus       = ceil(792.6 / 18)             = 45
nodes/Nexus       = ceil(45 / 2)                 = 23   (46 disks)
round up          = 24 nodes × 2 disks = 48 disks/Nexus (144 disks cluster)
provisioned raw   = 144 × 18                     = 2592 TiB
usable            = 2592 × 0.95 × 0.85 / 1.875   = 1116 TiB  (≈1.09 PiB)
```

**Single-site example (`1+0 × 16+4`, ratio 1.25, 18 TiB, 10 nodes × 2 disks):**

```
raw = 20 × 18 = 360 TiB → usable = 360 × 0.95 × 0.85 / 1.25 = 232.6 TiB
```

### 3.4 Non-capacity sizing

| Component | Sizing | Why |
|---|---|---|
| Gateway | 2+ per site, 2–4 vCPU, ~8 GiB memory limit with default offloader settings | per in-flight chunk ≈ 70 MiB for a 16 MiB chunk with `2+1 × 16+4` ([docs/03 §1.3](03-data-plane.md)); `offloaderWorkers=16` ⇒ ≈1.1 GiB heap plus crypto/RS overhead |
| Coordinator | 2–4 vCPU, 4–8 GiB, fast local disk (embedded store) or a managed PostgreSQL; 2 replicas with PostgreSQL, 1 with the embedded store | metadata-only; the embedded store is single-writer, PostgreSQL allows control-plane HA |
| Console | negligible (50–100 m CPU, 256 MiB) | server-rendered templates |
| Agent | 1–2 vCPU, ~512 MiB–2 GiB per disk, one process per disk | immutable shard I/O + repair workers |
| Network | private storage network; gateway→agent 7100+; client→gateway 8080/8443 | shard traffic dominates (≈ratio × object bytes) |

Ports and firewall summary: clients → gateway `8080/8443`; gateways → agents
`7100–71xx`; agents → coordinator `7000`; gateways/console → coordinator `7000`;
console ← operators `8081` (loopback/proxy). Prometheus scrapes gateway `9000`
and agent `71xx` `/metrics`.

---

## 4. Install: Kubernetes

### 4.1 Build/push the image

The multi-stage Dockerfile builds every binary into a distroless image:

```bash
docker build -f deploy/docker/Dockerfile -t registry.example.com/fass:0.1.0 .
docker push registry.example.com/fass:0.1.0
```

Set `image.repository`/`image.tag` in your values file.

### 4.2 Prepare disks and nodes

On every agent node (one directory per physical disk):

```bash
sudo install -d -o 65532 -g 65532 -m 0750 /var/lib/fass/disks/disk0 /var/lib/fass/disks/disk1
# the pods run as uid 65532 (distroless nonroot); hostPath volumes are NOT chowned by Kubernetes
```

Label nodes by site if you use `nodeSelector` for gateways:

```bash
kubectl label node node-a1 fass.io/nexus=nexus-a
```

### 4.3 Create the required Secrets

The chart never creates Secrets and deliberately fails rendering when a
reference is missing. Plain placeholders are for illustration only.

```bash
# Gateway tenant key seed: 64 hex chars. LOSING THIS MAKES EXISTING DATA UNREADABLE.
kubectl -n fass create secret generic fass-gateway-key-seed --from-literal=key-seed="$(openssl rand -hex 32)"
# (for a real install, import the seed you already custody — do not generate a new one on reinstall)

# Coordinator PostgreSQL DSN (only when coordinator.dbDriver=postgres; the chart
# mounts it as FASS_COORDINATOR_DB_DSN and the migrate hook consumes it).
kubectl -n fass create secret generic fass-coordinator-db-dsn \
  --from-literal=dsn='postgres://fass:CHANGEME@postgres.example:5432/fass?sslmode=require'

# Gateway TLS
kubectl -n fass create secret tls fass-gateway-tls --cert=gateway.crt --key=gateway.key

# Console HTTP Basic
kubectl -n fass create secret generic fass-console-auth \
  --from-literal=console-user=admin --from-literal=console-password="$(openssl rand -base64 24)"

# One announce secret per disk — created after registering the disk with the
# coordinator; see §4.4.
```

### 4.4 Register nodes and disks, then install

The coordinator is the source of truth for topology; the chart deploys
processes, it does not create cluster metadata. With PostgreSQL the chart's
`pre-install`/`pre-upgrade` Job runs `fass-coordinator migrate` before the
coordinator pods start (migrations are never applied implicitly on restart;
`dbMigrateOnStart` stays false). For systemd run it once explicitly:
`sudo -u fass sh -c '. /etc/fass/coordinator.env && exec /usr/local/bin/fass-coordinator migrate'`.

Bootstrap order:

```bash
COORD=http://coordinator.site-a.internal:7000

# 1. Swarm
curl -sS -X POST $COORD/v1/swarms -H 'Content-Type: application/json' \
  -d '{"name":"prod-swarm","region":"eu-west-1"}'
# → {"swarm_id":"...", ...}

# 2. Nexuses (one per site)
curl -sS -X POST $COORD/v1/nexuses -H 'Content-Type: application/json' \
  -d '{"swarm_id":"<swarm-id>","nexus_id":"nexus-a","name":"site-a","region":"eu-west-1"}'
# repeat for nexus-b, nexus-c

# 3. Nodes. node_id MUST equal the Kubernetes node name (the chart passes it
#    as --node-id from agents.nodes[].name).
curl -sS -X POST $COORD/v1/nodes -H 'Content-Type: application/json' \
  -d '{"node_id":"node-a1","nexus_id":"nexus-a","hostname":"node-a1","rack":"rack-a1"}'

# 4. Redundancy Class (immutable; geo 2+1 / local 16+4 / aag 2 / 16 MiB chunks)
curl -sS -X POST $COORD/v1/redundancy-classes -H 'Content-Type: application/json' \
  -d '{"name":"prod-rc","params":{"geo_n":2,"geo_k":1,"local_n":16,"local_k":4},"aag":2,"chunk_size":16777216}'

# 5. Per disk: register a pending agent and store its one-time announce secret.
curl -sS -X POST $COORD/v1/agents/pending -H 'Content-Type: application/json' \
  -d '{"node_id":"node-a1","disk_id":"disk0"}'
# → {"agent_id":"...","secret":"..."}
kubectl -n fass create secret generic fass-agent-node-a1-disk0 --from-literal=secret='<secret>'
```

Install and start the workloads:

```bash
helm install fass ./deploy/helm/fass -n fass -f my-three-site.yaml

# Agents announce as `pending`; activation is an explicit operator decision.
# (The console does this with CSRF-protected POSTs; or via the API.)
for id in $(curl -sS $COORD/v1/agents | jq -r '.agents[] | select(.state!="active") | .agent_id'); do
  curl -sS -X POST "$COORD/v1/agents/$id/activate"
done
```

Create the Ring **after** the agents are ACTIVE (the coordinator auto-fills ring
membership from active agents in the listed Nexuses and sums their capacity):

```bash
curl -sS -X POST $COORD/v1/rings -H 'Content-Type: application/json' \
  -d '{"name":"prod-ring","rc_id":"<rc-id>","nexus_ids":["nexus-a","nexus-b","nexus-c"]}'
```

Then create tenants/projects/buckets/access keys through the coordinator API
(`POST /v1/tenants`, `POST /v1/buckets` with `default_rc_id`, `POST
/v1/access-keys`). S3 access keys are **not** injected into any pod: they are
client credentials, custody them in your secret manager.

### 4.5 Verify

```bash
kubectl -n fass get pods -o wide
kubectl -n fass rollout status deploy -l app.kubernetes.io/component=gateway

fass --endpoint https://s3.site-a.example health
fass --coordinator $COORD cluster status           # expect N total, N ACTIVE, ring, RC ratio
curl -fsS $COORD/v1/repair/status | jq .
curl -fsS -u admin:<pw> http://console:8081/ | grep -c 'Cluster overview'
```

---

## 5. Install: systemd

[docs/08](08-operations.md#2-boot-a-dev-cluster) covers the dev recipe;
[deploy/systemd/README.md](../deploy/systemd/README.md) is the full install
guide. The essentials:

```bash
make build
sudo install -m 0755 bin/fass-{coordinator,gateway,console,agent} /usr/local/bin/
sudo useradd --system --home-dir /var/lib/fass --shell /usr/sbin/nologin fass
sudo install -d -o fass -g fass -m 0750 /var/lib/fass /etc/fass
sudo install -m 0644 deploy/systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload

# coordinator (site A only)
sudo install -m 0640 -o root -g fass deploy/systemd/examples/coordinator.env.example /etc/fass/coordinator.env
sudo systemctl enable --now fass-coordinator
# gateways (each site), then console (loopback + TLS proxy)
sudo install -m 0600 -o root -g fass deploy/systemd/examples/gateway.env.example /etc/fass/gateway.env
sudo systemctl enable --now fass-gateway
# one unit instance per disk, each with its own env file and port
sudo install -m 0600 -o root -g fass deploy/systemd/examples/agent.env.example /etc/fass/agent-disk0.env
sudo systemctl enable --now fass-agent@disk0
```

Logs are in the journal (`journalctl -u fass-coordinator -f`,
`journalctl -u fass-agent@disk0 -f`); see the README for the disk layout
convention (`/var/lib/fass/disks/<instance>`), which the units use for
`RequiresMountsFor=` and `ReadWritePaths=`.

---

## 6. Upgrade order (and why)

**Coordinator → gateways → agents**, gated by health checks after each step.

1. **Coordinator first.**
   * It owns the schema. With PostgreSQL the chart's `pre-upgrade` hook applies
     migrations *before* the new pods start; with the embedded store the
     process migrates at boot. New coordinator releases keep the API backwards
     compatible, so old gateways/agents keep working during the window.
   * The gateway tolerates a short coordinator outage (hmac-key and manifest
     caches, ≤60 s), so a rolling restart is visible but not fatal to reads.
   * Take a database snapshot/backup *before* upgrading: with PostgreSQL that is
     a normal `pg_dump`/snapshot; with the embedded store it is the PVC
     snapshot. This is the rollback point.
   * PostgreSQL replicas roll one at a time (`maxUnavailable: 0`). With the
     embedded store (single replica, `Recreate`) expect a brief
     placement/commit pause — do it in a quiet window, not during a migration.

2. **Gateways next.**
   * They are stateless: nothing to migrate, and `maxUnavailable: 0` (chart) or
     an LB drain lets in-flight requests finish.
   * Restart one at a time / drain from the load balancer first. `readyz` checks
     the coordinator, so a gateway that comes up while the coordinator is
     unhealthy will not receive traffic.
   * Key-seed and RC parameters must remain identical across the rollout.

3. **Agents last, one failure domain at a time.**
   * Restarting an agent stops its heartbeats: the coordinator marks it SUSPECT
     after 15 s and OFFLINE after 60 s, which starts the repair clock for every
     shard set it hosted.
   * Never restart a whole Nexus (or two nodes in the same Nexus) together:
     that is exactly the failure the geo tier exists to survive, and you would
     be trading a controlled upgrade for an incident.
   * Between batches wait for the agent to be ACTIVE again and for
     `/v1/repair/status` backlog to return to a low, steady value. Do not
     continue while `failed` is climbing or `unrecoverable` is non-zero.
   * Agents persist identity + shards; a binary upgrade does not touch
     `state.json`. The unit's `ExecStartPre` only checks environment/mount; the
     agent itself fails closed on an identity mismatch.

```bash
# Kubernetes, coordinator then gateways then agents (one node at a time)
kubectl -n fass set image deploy/fass-coordinator coordinator=<image>
kubectl -n fass rollout status deploy/fass-coordinator
kubectl -n fass set image deploy/fass-gateway gateway=<image>
kubectl -n fass rollout status deploy/fass-gateway
# agents: the chart renders one Deployment per node; bump a batch, wait, repeat
kubectl -n fass set image deploy/fass-agent-node-a1 agent-0=<image>,agent-1=<image>
kubectl -n fass rollout status deploy/fass-agent-node-a1
# then node-a2, ..., then site B, site C

# systemd
sudo systemctl restart fass-coordinator && systemctl is-active fass-coordinator
sudo systemctl restart fass-gateway
# one disk at a time, waiting for ACTIVE in `fass cluster status`
sudo systemctl restart fass-agent@disk0
```

## 7. Rollback

* **Agents / gateways**: reinstall the previous binary/image; stateless. Rolling
  back one agent at a time follows the same rule as upgrading.
* **Coordinator**: the safe rollback point is the **database backup/snapshot
  taken before the upgrade**. Migrations are forward-only (both backends): if
  the new release ran one, an older binary may not understand the schema —
  restore the backup (losing writes since the snapshot) or roll forward with a
  fixed build. Check before/after:

  ```bash
  curl -fsS http://coordinator:7000/v1/healthz | jq .schema_version
  ```

* **Helm**: `helm history fass -n fass` and `helm rollback fass <revision> -n
  fass`. PVCs are retained; the coordinator Deployment uses `Recreate`, so no
  two pods ever mount the store simultaneously.
* Never delete a coordinator PVC as a "reset": that is the cluster metadata
  (buckets, manifests, access keys). Shards alone cannot reconstruct objects.

## 8. What NOT to do

| Don't | Why |
|---|---|
| Change an RC's `geo_n/geo_k/local_n/local_k/aag/chunk_size` in place | RCs are immutable by design. Create a **new RC** and a **new Ring**, point new writes at it (bucket default RC / SDP rule), and migrate data by rewrite. |
| Shrink or "resize" a Ring in place | Ring capacity is derived from its agents; grow by adding a new Ring for the same RC (docs/03 §4.6). |
| Run two coordinator replicas against the embedded store | The embedded store is single-writer; a second replica corrupts or fights the first. Scale only with `dbDriver=postgres`. |
| Skip `fass-coordinator migrate` before a new coordinator binary | Migrations are explicit by design; a restart never mutates the schema. The chart runs the hook, systemd installs must run it. |
| Put more than one agent on a disk | Shard addresses and `state.json` are per-agent; two agents on one disk race and fail closed. |
| Spread one shard-set wider than `aag` per node "for safety" | Placement will not use the extra slots; size by **nodes**, not disks. |
| Restart a whole Nexus during an upgrade | That is a site-loss event; repair starts while you are still upgrading. |
| Rotate/replace the gateway key seed casually | Existing objects were encrypted under it and become unreadable. Seed custody is a first-class secret. |
| Expose the coordinator (7000) or console (8081) directly to the internet | Coordinator admin is unauthenticated; console has one shared Basic credential and no TLS. |
| Delete `/var/lib/fass` (coordinator) or an agent's `state.json` to "fix" a failure | That deletes metadata/identity. Restore, don't reset. |
| Upgrade all agents in one `rollout restart` | Starts repair storms and may make a shard set temporarily unreadable beyond `local_k`. |

## 9. Day-2 checks

| Check | Command | Healthy looks like |
|---|---|---|
| Cluster health | `fass --coordinator URL cluster status` | agents `N total, N ACTIVE`; no SUSPECT/OFFLINE; RC ratio as designed |
| Agent states | same output / console `/agents` | all ACTIVE, last heartbeat seconds ago |
| Repair queue | `curl -s URL/v1/repair/status \| jq .` | `queue.pending` low/steady, `failed=0`, `shardsets.unrecoverable=0` (**non-zero = data loss, page someone**) |
| Ring fullness | `fass --coordinator URL cluster status` | ring FULL < 85%; above that, place a new Ring |
| Disk pressure | `curl -s http://agent:71xx/metrics \| grep fass_agent_\(free\|used\)_bytes` | free bytes comfortably above reserve |
| Scrub | `curl -s http://agent:71xx/v1/stats \| jq .` | scrub cursor advancing (period default 7 days); `POST /v1/scrub` kicks an ad-hoc pass |
| Gateway readiness | `curl -fsS http://gw:9000/readyz` | `{"status":"ready"}` (coordinator reachable) |
| Coordinator errors | `curl -s URL/metrics \| grep 'status="5'` | no unexplained 5xx growth |
| Console | open `/`; red banner means coordinator unreachable, red repair card means data loss | green/amber; degrade is by design, it should not white-screen |

Capacity growth: when a Ring crosses 85%, create a new Ring for the same RC and
let new placements land there; do not modify the old one. Use SDP rules (or
bucket defaults) to route new writes if you have multiple Rings/RCs.

## 10. Known product gaps

These are the places where this guide has to work around the current product.
They are the follow-ups that matter for a real 3-site install; the chart fails
loudly rather than pretending they are supported.

1. **PostgreSQL support is new.** The coordinator now supports
   `--db-driver=postgres` (+ `fass-coordinator migrate`), but the embedded store
   remains the dev default and PostgreSQL is not bundled or operated by this
   chart: provide a managed/HA PostgreSQL (with backups and failover tested),
   create the DSN Secret, and run migrations through the chart hook (or the
   subcommand for systemd). Validate failover and upgrade paths in staging
   before relying on it for the control plane.
2. **No TLS/mTLS on the coordinator** (docs/07 describes mTLS for production).
   Coordinator↔gateway/agent traffic must be wrapped by a private network, VPN
   or service mesh; add TLS flags before exposing a coordinator across sites.
3. **Agent has no environment/secret-file configuration.** It reads flags only,
   so (a) the Helm chart renders one pinned Deployment per node instead of one
   DaemonSet per Nexus (each disk has a distinct one-time announce secret, and
   Kubernetes cannot vary a `secretKeyRef` per DaemonSet pod), and (b) the
   systemd unit and pod spec expand the announce secret into the process
   command line. A `--secret-file` (or env-var configuration) would let the
   chart collapse to one DaemonSet per Nexus and keep secrets out of argv.
4. **No KMIP/key service.** Only `--key-seed`/`FASS_GATEWAY_KEY_SEED` static
   single-key mode exists; KMIP 1.4 (docs/03 §3.3) is not implemented. Today
   the seed is a manually custodied secret; the chart requires its Secret.
5. **Console is single-credential Basic auth, no TLS, no RBAC/OIDC.** Bind to
   loopback/private and front with a TLS reverse proxy + SSO. (Tracked as
   multi-tenant console work, not a deployment bug.)
6. **No object-store/Ingress resources in the chart.** The chart exposes
   ClusterIP services and leaves LB/Ingress/TLS-termination choices to the
   platform; this is deliberate, but means "install + expose to clients" is two
   steps.
7. **`deploy/docker/compose.dev.yml` is stale** relative to the binaries: it
   passes flags that do not exist (`--dev`, `--dev-topology`, `--default-rc`,
   agent `--listen`) and environment variables the agent does not read
   (`FASS_COORDINATOR_URL`, `FASS_AGENT_SECRET`). The working dev path is
   `scripts/smoke-cluster.sh` / docs/08. (Reported to the Lead; outside this
   task's write scope.)

## 11. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `helm template` fails with "coordinator.replicas > 1" | tried to run an HA control plane | stay at 1 replica until the Postgres backend lands |
| Pods `CreateContainerConfigError` / missing Secret | chart references a Secret that does not exist | create the key-seed/TLS/console/agent Secrets listed in §4.3 |
| Agent pod CrashLoopBackOff, log "identity mismatch"/"refusing" | disk reused with a different `state.json` identity | use the identity that owns the disk; never delete `state.json` to bypass |
| Agent announces `pending` and stays there | activation is explicit | `POST /v1/agents/{id}/activate` (or the console) |
| Placement fails `507 … not enough eligible nexuses/agents` | declared topology < RC requirement, or agents not ACTIVE | check `nodes ≥ ceil((local_n+local_k)/aag)`, agents ACTIVE, ring spans `geo_n+geo_k` Nexuses |
| Gateway 503 on writes, `/readyz` not ready | coordinator unreachable from gateway | fix `coordinatorURL`/network; check `/v1/healthz` |
| TLS handshake errors | certificate Secret keys/format | Secret must be `kubernetes.io/tls` (tls.crt/tls.key) or match `gateway.tls.certKey/keyKey` |
| Ring stops accepting writes at ~85% | design watermark | create a new Ring for the same RC; do not edit the old one |
| Console page red banner | coordinator unreachable | expected degraded mode; fix coordinator connectivity |
| Console repair card red ("unrecoverable") | a shard set lost more than `geo_k` groups | **data loss**: stop deletions, preserve disks/logs, use backups; do not run repair expecting recovery |

---

## PostgreSQL metadata backend

The coordinator ships two persistence backends behind the same `storage.Store`
interface: the embedded WAL engine (`--db-driver=embedded`, the dev default,
single process, one data directory) and PostgreSQL (`--db-driver=postgres`).
ADR-3b in [docs/02-architecture.md](02-architecture.md) records why the v1
adapter stores records in the documented `kv`/`blobs` layout instead of querying
the entity relations directly, and what that costs.

### What was actually tested

| Configuration | Evidence |
|---|---|
| One coordinator process, one PostgreSQL 16 primary, embedded and PostgreSQL backends | repository parity suite (`internal/coord/meta/parity`) runs the same behaviour tests against both backends, including two concurrent commits to the same key; PostgreSQL runs `EXPLAIN` assertions that point gets, version range scans and prefix listings are index scans |
| Coordinator on PostgreSQL serving the full S3 surface | `go test -tags=compat ./test/compat/` 21/21 and `scripts/compat.sh` PASS (aws-cli, rclone incl. tree sync, s3cmd) with `FASS_COMPAT_POSTGRES_DSN` set |
| Lifecycle expiry + object lock on PostgreSQL | included in the compat suite above, including the dev-gated clock restart |
| Crash-restart of the coordinator | the metadata transaction is the durability boundary; a restart reconnects to PostgreSQL and re-runs no migrations by default |
| **Ungraceful primary crash + promotion** (`docker kill`, `pg_ctl promote`) | HA drill below: detection 150–170 ms, RTO 456–482 ms, RPO 0/20 acknowledged objects, plus the outage behaviour (health 503, retryable writes) |
| **pg_dump / pg_restore metadata round trip** | HA drill below: restored database served the same 20 objects byte-identically |

### Not tested (do not assume these work)

The failover/restore drill below closes the previous "no failover, no restore
drill" gap **for the control-plane metadata path**. It does not close these:

* **No load/latency test of the adapter.** Statement timeouts are set (default
  5 s, `--db-statement-timeout`) and the pool is bounded (defaults 40 open /
  10 idle, `--db-max-open-conns/--db-max-idle-conns`); capacity is not measured.
* **No gateway-level failover test.** The drill drives the coordinator HTTP API
  directly (metadata commits/reads); it does not start gateways/agents, so the
  gateway's retry/error mapping during a database outage is still unverified.
* **No floating-endpoint (proxy) failover.** The drill restarts the coordinator
  against the promoted standby; the no-restart VIP/DNS variant is documented but
  not exercised.
* **No asynchronous-replication RPO measurement.** RPO 0 was observed with a
  synchronous standby; an async standby's loss window under the same crash is not
  measured, and neither is split-brain prevention (that is database topology
  configuration, out of FASS's control).
* **No cross-version migration run** (only the initial migration exists).
* **No long-running PITR drill.** The restore drill uses `pg_dump`/`pg_restore`
  (physical/logical backup round trip), not WAL-archive PITR to a past timestamp.

### Starting the PostgreSQL-backed coordinator

```bash
# 1. One-time (and per upgrade): apply migrations explicitly. Never on boot in
#    production; the server defaults to --db-migrate-on-start=false.
fass-coordinator migrate --db-dsn "postgres://fass@db1:5432/fass?sslmode=verify-full"

# 2. Run the coordinator against it.
fass-coordinator \
  --db-driver=postgres \
  --db-dsn "postgres://fass@db1:5432/fass?sslmode=verify-full" \
  --db-max-open-conns 40 --db-max-idle-conns 10 \
  --db-statement-timeout 5s
```

A bad DSN or a missing schema fails at startup with an actionable error; it never
surfaces as a 500 on the first write. `--db-migrate-on-start=true` exists only for
single-node/dev deployments and CI; it is deliberately not the default. The
embedded backend still migrates its own store on open (there is no separate
process for it).

### Primary/standby and RPO

For RPO 0 within one region, run PostgreSQL with a synchronous standby:

```
synchronous_commit = on            # default; a commit is durable on the primary
synchronous_standby_names = '1 (standby1)'
```

FASS's commit is the single act that publishes an object; with
`synchronous_commit=remote_apply` a 204 from the coordinator means the metadata
is on the standby too, at the cost of commit latency. With the default
`synchronous_commit=on` RPO is 0 on the primary's disk but a primary loss can
lose the last asynchronous standbyship transactions, so use a synchronous standby
if losing the last commits is unacceptable.

### Failover behaviour (observed in the drill)

* **The coordinator detects the loss on the next request, not by a background
  probe.** In the drill, `/healthz` returned `503` with
  `{"status":"unhealthy","database":"unreachable"}` within **150 ms** of the
  ungraceful kill (the very first health poll after the crash).
* **Writes fail fast and are retryable.** A metadata commit while the primary was
  down returned **503 `ServiceUnavailable` in ~252 µs**, not a 500 and not a
  hang. The coordinator maps backend connectivity failures ("connection reset",
  connection-refused, PostgreSQL class 08/57P0x, pool closed) to `storage.ErrUnavailable`
  → 503, so a client/SDK retry is the correct response. Reads fail the same way.
* **A coordinator restart is required to follow the promoted primary** (or a
  floating endpoint). Coordinators do not elect a new primary themselves; they
  are clients of one primary. Two coordinators writing to different primaries is
  split-brain and must be prevented by the database topology.
* **Gateways are stateless** (they hold no database connection; they call the
  coordinator HTTP API), so a coordinator restart is transparent to their
  configuration, but the gateway-level retry/error mapping during a DB outage was
  **not exercised** by this drill — see "Not tested".
* **Agents** hold no metadata and are unaffected apart from the pause in
  control-plane responses.
* **Agents** retry heartbeats and re-announce if needed; they hold no metadata
  and are unaffected by a database failover apart from the pause in control-plane
  responses.
* **Repair state** (`/v1/repair/status`) is in coordinator memory and resets on
  restart; the queue itself is database-backed once the orchestrator lands.

### Measured failover and restore drill (2026-10-24)

Reference run, reproducible with `go test -tags=ha -count=1 ./test/ha/ -v`
(docker required; the test skips cleanly when it is unavailable):

* Two `postgres:16` containers on one docker network: primary with
  `wal_level=replica`, a synchronous streaming standby
  (`synchronous_commit=on`, `synchronous_standby_names='*'`), and the coordinator
  (`fass-coordinator --db-driver=postgres`) in front of the primary. The drill
  drives the coordinator HTTP API directly (20 committed metadata objects + a
  versioned bucket; no gateways/agents are started).
* Kill: `docker kill <primary>` — an ungraceful crash, no checkpoints/shutdown.
* Promotion: `docker exec --user postgres <standby> pg_ctl promote -D /pgdata`,
  then the coordinator is restarted against the standby DSN (same listen port).

| Measurement | Result |
|---|---|
| Health detection (`/healthz` first non-200 after `docker kill`) | **150–170 ms** |
| Promotion detected (first writable probe on the standby) | **134–155 ms** |
| Write-unavailability window (last 200 before kill → first 200 after repoint) | **456–482 ms** |
| RTO (kill → first successful write) | **456–482 ms** |
| RPO | **0 of 20 acknowledged objects lost**; all byte-identical after promotion |
| Outage write behaviour | **503 ServiceUnavailable in 252–354 µs** (retryable, bounded) |
| Object that errored during the outage | cleanly absent (404) after recovery — no partial manifest |
| Restore drill (`pg_dump -Fc` → `pg_restore` into a fresh DB → coordinator → reads) | dump ~10.5 KB, **416–471 ms** end-to-end; all 20 objects byte-identical |

Ranges are across three consecutive reference runs, not a statistical sample.

These are single-run numbers from a dev-mode coordinator (embedded bootstrap,
plaintext listener) on one machine, with tiny objects; they measure failover
*mechanics*, not a production SLO. Reproduce:

```bash
# Requires docker (starts and cleans up its own containers/network/volume).
go test -tags=ha -count=1 ./test/ha/ -v
# look for the MEASURED lines in the output
```

### Backups and PITR

Use PostgreSQL's own tooling: continuous WAL archiving (pgBackRest, WAL-G, or
managed service PITR) plus periodic base backups. FASS metadata is one database;
there is no separate coordinator-side export. Test the restore procedure on a
staging cluster before relying on it: restoring a metadata snapshot to a older
point makes previously visible objects invisible again (shards are immutable and
still on the agents; re-commit is not automatic). Object data itself lives on the
agents' disks and has its own availability story (redundancy class), independent
of the database.

### Autovacuum / bloat

Version deletion, tombstones and overwrites make `kv` write-heavy. The migration
sets aggressive per-table autovacuum (`autovacuum_vacuum_scale_factor=0.02`,
`autovacuum_analyze_scale_factor=0.01`, `autovacuum_vacuum_cost_limit=2000`).
Monitor `pg_stat_user_tables.n_dead_tup` and `pg_stat_activity` for long-lived
transactions that hold back vacuum; a coordinator with a stuck statement (the
5 s statement timeout should prevent it) will bloat the table. Tune the settings
for the table size on the actual cluster; the migration values are a starting
point, not a universal answer.

### Load-test results (PostgreSQL adapter, measured 2026-10-24)

First ceiling measurement of the PostgreSQL-backed coordinator under a mixed S3
workload (disposable `postgres:16` with `shared_buffers=256MB`, coordinator,
12 agents, 2 gateways; 60 s measured window after 20 s warmup). Full per-phase
table, JSON artifact, contention analysis and gate results:
[`test/load/REPORT.md`](../test/load/REPORT.md). Reproduce with `make load`
(or `go test -tags=load -count=1 ./test/load/ -v`).

**Headline numbers (one reference run; ±2× run-to-run variance on a shared box —
report a ceiling, not an SLO):**

| op | p50 | p99 | throughput |
|---|---:|---:|---:|
| PUT (4 KiB / 1 MiB / occasional 12 MiB) | 662 ms | 958 ms | 48 ops/s (10.9 MiB/s) |
| GET (hot + random) | 44 ms | 168 ms | 315 ops/s (66.5 MiB/s) |
| ListObjectsV2 (paged) | 342 ms | 588 ms | 17 ops/s |
| version listing (coordinator API) | 120 ms | 228 ms | 16 ops/s |
| read-only GET phase | 19 ms | 109 ms | 690 ops/s |

**Hard gates all passed:** 200/200 sampled PUT→GET byte-identical; **0**
non-retryable 5xx (and 0 retryable 503 in this run); **0 deadlocks**, max 39 lock
waiters capped by the 40-connection pool during the 200-way single-key contention
storm (serialized-by-design signature, not a convoy); max 41/200 PostgreSQL
connections (no exhaustion); `kv` dead tuples 33 → 963 peak → **17** after
autovacuum (reclaimed); no repair/scrub interference.

**What this does not show:** a longer/sustained churn run (bloat under hours of
tombstones), degraded/failed-disk conditions, WAN latency between sites, or
failover under load. HA-under-load is the natural next drill: the workload
harness can be combined with the `test/ha` crash/promote sequence to measure the
client-visible error/latency spike across the measured 456–482 ms failover window.
