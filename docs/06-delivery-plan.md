# 06 — Delivery Plan

How we get from this design to a working geo-distributed S3 in Go, in what order, with what proof at each step.

---

## 1. Repository layout

Single Go module: `github.com/<org>/fass` (module path to be confirmed).

```
fass/
├── cmd/
│   ├── fass-gateway/          main: S3 frontend
│   ├── fass-coordinator/      main: control plane
│   ├── fass-agent/            main: per-disk shard daemon
│   ├── fass-console/          main: web UI
│   ├── fass-cli/              main: `fass` binary
│   ├── fass-bridge/           main: S3→FASS migration
│   ├── fass-operator/         main: k8s operator
│   └── fass-all/              main: single-process dev/eval mode
├── api/
│   ├── proto/fass/v1/         coordinator.proto, agent.proto, placement.proto, repair.proto
│   └── gen/                   buf-generated Go
├── internal/
│   ├── gateway/
│   │   ├── s3/                routing, handlers per operation, xml types
│   │   ├── sigv4/             SigV4 + SigV2 + presign + chunked signing
│   │   ├── authz/             decision cache, CRN, policy eval
│   │   ├── offloader/         write/read pipeline
│   │   ├── sdp/               Smart Data Placement rule engine
│   │   └── cache/
│   ├── coord/
│   │   ├── api/               gRPC + REST handlers
│   │   ├── auth/              tenants, users, keys, policies
│   │   ├── meta/              repositories, SQL, migrations
│   │   ├── placement/         filters, scorer, rings
│   │   ├── membership/        announce, heartbeat, health
│   │   ├── recovery/          repair orchestration
│   │   ├── usage/             accounting rollups
│   │   └── blobstore/         content-addressed manifest pages
│   ├── agent/
│   │   ├── store/             pebble index + shard files
│   │   ├── transport/         quic + grpc servers
│   │   ├── repair/            job executor
│   │   └── scrub/
│   ├── chunk/                 chunker, frame layout
│   ├── ec/                    two-tier RS encode/decode (pure, no I/O)
│   ├── crypto/                AES-GCM framing, HKDF, envelope, KMIP
│   ├── topology/              swarm/nexus/node/agent model + validation
│   ├── policy/                IAM/bucket/ACL evaluation
│   ├── storage/               repository interfaces (postgres + sqlite)
│   ├── obs/                   slog, prometheus, otel
│   ├── config/                one config struct, vulidated
│   └── testutil/              fake clock, in-proc transport, fixtures
├── pkg/sdk/                   Go client SDK (equivalent of "Cubbit SDK")
├── deploy/
│   ├── docker/compose.dev.yml
│   ├── helm/fass/
│   └── ansible/               node deployment templates
├── test/
│   ├── e2e/                   docker-compose driven
│   ├── compat/                ceph/s3-tests + our divergence suite
│   ├── chaos/                 kill agent/node/nexus
│   └── bench/
├── docs/                      this design set + ADRs + schema.sql
└── Makefile                   build, lint, test, e2e, compat, images
```

**Dependency rule:** `internal/ec`, `internal/crypto`, `internal/chunk`, `internal/topology`, `api/proto` are the *contract layer*. They are written first, frozen, and owned by the Lead. Feature teams own disjoint directories below them.

---

## 2. Milestones
### 2.0 Approved revision (2026-10-24)

The user approved implementation with three changes to the ordering below. They are binding:

| Decision | Effect on the plan |
|---|---|
| **D-A: two-tier from the first data path.** No flat-only intermediate milestone. | M3 (single-tier) is removed. The first end-to-end object path uses `geo 2+1 × local 16+4` on a simulated 3-Nexus topology (3 agent groups on one host in dev). Flat coding remains expressible but is never the only working path. |
| **D-B: incremental S3 matrix, system always runnable.** | Every merge must keep `make build vet test` green and `fass all` bootable. Operations are added in dependency order; not-yet-implemented operations return `501 NotImplemented` — which is *also* the Cubbuilt-compatible answer for 54 of them, so the surface is honest at every step. |
| **D-C: PostgreSQL + embedded dev store.** | Production system of record is PostgreSQL (sync standby in-region). Dev mode uses a dependency-free embedded journal store behind the same repository interfaces, clearly marked dev-grade. SQLite is **not** used (avoids a ~40 MB vendored CGo/pure-Go driver); the embedded store is narrower and honest about its durability. |

Consequence: milestones are re-sequenced as M0 → M1/M2 (control plane and agent in parallel) → M2.5 (two-tier object path) → M3 (3-site topology, RC/Rings, placement) → M4 (S3 matrix) → M5 (durability) → M6 (ops) → M7 (hardening). The M-numbering below is retained for the exit criteria, but M3's "single-tier" scope is superseded by D-A.

Dev topology (corrected after a feasibility analysis — the first spec was arithmetically impossible):

* 3 simulated Nexuses (`nexus-a`/`-b`/`-c`) × 2 nodes × **2 disks per node = 12 agents**.
* Dev Redundancy Class `geo 2+1 / local 3+1`, `aag 2`, **chunk 6 MiB** ⇒ 12 shards per chunk, ratio 2.0, 1 MiB per shard exactly.
* Why these numbers: per-Nexus shard capacity is `min(#agents, #nodes × aag)` because a shard set places at most one shard per Agent, so `local_n + local_k = 4` needs 4 agents in every Nexus. `geo_n · local_n = 6` must divide the chunk size for uniform shards, and **no power-of-two chunk is divisible by 6** — hence 6 MiB, and the RC validator's power-of-two rule was replaced by the real contract (1 MiB alignment, 4–64 MiB, shard ≥ 4 KiB).
* The resulting test is stronger than a tidy degrade: killing one node leaves 2 of 4 shards (< `local_n = 3`), so that entire Nexus group is unusable and the read must reconstruct through the outer code from the other two Nexuses. Killing `nexus-c` leaves exactly `geo_n = 2` groups.


Effort in engineer-days for one experienced Go engineer. Calendar estimates assume 3 parallel workstreams.

### M0 — Bootstrap (2 d)
Repo, module, CI (lint/vet/test/race), `buf` codegen, config loader, health endpoints, structured logging, `make dev` bringing up coordinator+gateway+6 agents on loopback, `docker compose`.
**Exit:** `curl localhost:8080/healthz` on every service; CI green.

### M1 — Control-plane spine (6 d)
Postgres schema + migrations, tenants/projects/users/access keys, CRN + policy evaluation unit-tested, bucket CRUD in metadata, swarm/nexus/node/agent/ring/RC lifecycle, agent `announce` + heartbeat + pending→active flow, audit log.
**Exit:** an agent announces, is activated, appears in `fass node ls`, and heartbeats survive a coordinator restart. Policy tests cover the four-stage chain.

### M2 — Agent v1 (6 d)
Shard store (Pebble + immutable files), QUIC + gRPC transport with mTLS, `PutShard/GetShard/DeleteShards/HasShards/Inventory`, crash-safety (`partial` sweep), capacity accounting, one-per-disk enforcement via disk UUID.
**Exit:** 10k random shards written/read/verified with `--race`; kill -9 during write leaves no corrupt shard; disk-swap is refused.

### M3 — End-to-end single-tier object path (8 d)
`internal/ec` (flat code first), `internal/crypto` (AES-GCM framing, envelope), chunker, offloader write/read, placement v1 (dedupe by agent, free capacity, aag), `PutObject/GetObject/HeadObject/DeleteObject/ListObjectsV2`, SigV4 verification, XML error envelope.
**Exit:** `aws s3 cp` a 1 GiB file and read it back byte-identical; `aws s3 ls`; range GET; ETag correct; killing one agent still reads (with `local_k ≥ 1`).

### M4 — Two-tier EC, Rings, Redundancy Classes (8 d)
Geo tier encode/decode, RC validation matrix, rings + capacity/`ring_full_pct`, `geo_n`/`geo_k`/`aag` constraints enforced, geo-fencing, Nexus model, displacement handling, deterministic placement + replay, Smart Data Placement rule engine.
**Exit:** `geo 2+1 / local 16+4` cluster across 3 simulated Nexuses: kill an entire Nexus, object still readable from 2. Ratio and shard counts match the spec exactly; placement invariants (AAG, distinct Nexus, geo-fence) hold under property tests.

### M5 — S3 surface completion (8 d)
Multipart (all 5 ops + `UploadPartCopy`), versioning (UUIDv4 ids, delete markers), object lock (GOVERNANCE/COMPLIANCE/legal hold, extend-only, bypass), ACLs + ownership controls (default `ObjectWriter`), tagging, `NoncurrentVersionExpiration` lifecycle, conditional requests, checksum verification, presign, SigV2.
**Exit:** the full supported-operation matrix passes against `aws-sdk-go-v2` and `rclone`; the `cubbit-strict` compat mode reproduces the ignore-headers behaviour for divergence tests.

### M6 — Durability loop (7 d)
Inventory digests, redundancy monitor with Cubbit thresholds (`n + k/2` per tier), repair scheduler with CAS generations, local repair (agent P2P), geo repair (gateway), scrubber, GC queue, rebalance/drain.
**Exit:** chaos suite: kill 1 disk → repaired within 4 h simulated (fast clock); kill a Nexus → geo repair completes; no object ever unreadable while within `k`; repair traffic stays under budget; orphan GC reclaims ≥ 99% of aborted-upload bytes.

### M7 — Operations surface (7 d)
Console (tenants, swarms, nexuses, nodes wizard with Ansible tar, RCs with ratio preview, gateway/SDP editor, usage charts), `fass` CLI, Prometheus metrics for every SLO, OTel traces, usage accounting (256 KB minimum, byte-hours, egress), alerting rules, k8s operator, Helm chart.
**Exit:** an operator can build a 3-site cluster from the console + generated Ansible bundle without touching the CLI; Grafana dashboard shows the SLOs; usage report matches an independent byte count.

### M8 — Hardening (8 d)
Chaos (network partitions, clock skew, disk full, slow disk, coordinator failover), `ceph/s3-tests` subset, fuzz (SigV4 canonicalisation, XML, SDP parser, shard header), benchmarks + capacity planning guide, security review, runbooks, threat model.
**Exit:** 24 h soak under mixed workload with zero data loss; p99 targets met; all fuzzers clean for 10⁷ execs; failover RTO ≤ 60 s measured.

**Total ≈ 60 engineer-days ≈ 12 person-weeks of focused work; ~5–6 calendar weeks with three parallel streams plus review/integration overhead.**

---

## 3. Parallel workstreams and write scopes

| Stream | Owns (write scope) | Depends on |
|---|---|---|
| **A. Gateway** | `internal/gateway/**`, `cmd/fass-gateway/**` | contract layer, coordinator API |
| **B. Coordinator** | `internal/coord/**`, `cmd/fass-coordinator/**` | contract layer, schema |
| **C. Agent** | `internal/agent/**`, `cmd/fass-agent/**` | contract layer, agent proto |
| **D. Platform** | `deploy/**`, `test/**`, `cmd/fass-console`, `cmd/fass-cli`, `cmd/fass-operator` | A/B/C interfaces |
| **Lead** | `internal/{ec,crypto,chunk,contract,policy}`, `api/**`, `docs/**`, `deploy/**`, `Makefile`, `scripts/**` | — |

**Scope note (2026-10-24):** `internal/topology` is deliberately *not* a separate
package. The topology model (Swarm→Nexus→Node→Agent→Ring) lives in
`internal/coord/membership`, where it is owned and evolved by the coordinator
stream; duplicating it in a shared package would have created two sources of
truth for the same invariants. Likewise there is no shared `config`/`obs`
package in v1 — each binary parses its own flags with `log/slog` and a small
Prometheus handler, which is less code than the abstraction.

**Freeze discipline:** the protos and the `ec`/`crypto`/`chunk` signatures are frozen at end of M0. Any change goes through the Lead and a proto version bump (`fass.v1` → additive only). This is what lets three agents work without merge chaos.

---

## 4. Test strategy

| Layer | What | Tooling | Gate |
|---|---|---|---|
| Unit | EC round-trips with random erasures; crypto framing/AAD; placement filters; policy eval; SDP operators | `go test -race` | every PR |
| Property | placement invariants (AAG, geo-fence, determinism, capacity); RS linearity; encode(decode(x)) == x | `testing/quick` | every PR |
| Fuzz | SigV4 canonical request, XML decode, chunk/shard headers, SDP JSON | `go test -fuzz` | nightly, 10⁷ execs |
| Integration | metadata against real Postgres; agent against real filesystem; multi-agent loopback transport | testcontainers | every PR |
| E2E | docker-compose 3-site cluster through the S3 API | `test/e2e` | pre-merge |
| Compatibility | `ceph/s3-tests` supported subset + divergence suite (`cubbit-strict` vs `fass`) | python venv, CI | nightly |
| Client conformance | `aws-cli`, `aws-sdk-go-v2`, `rclone`, `s3cmd`, `minio-go` | scripted | weekly |
| Chaos | kill agent/node/nexus, partition, clock skew, disk full, coordinator failover | `test/chaos` | pre-release |
| Performance | encode throughput, shard PUT/GET p99, gateway req/s, list at 10 M objects | `vegeta`, `pprof`, bench harness | pre-release |
| Soak | 24 h mixed workload with continuous verification | e2e harness | pre-release |

**Definition of done for any milestone:** tests added, `make lint test e2e` green, docs updated, and the milestone's exit criterion demonstrated by a script committed under `test/`.

---

## 5. Performance targets (to be validated, not asserted)

| Path | Target | Where measured |
|---|---|---|
| Gateway PUT throughput | ≥ 2 GB/s per 16-vCPU gateway with `geo 1+0` | bench harness |
| Gateway GET throughput | ≥ 4 GB/s per gateway, cache warm | bench |
| RS encode | ≥ 3 GB/s per core-scale (`local 16+4`) | microbenchmark |
| AES-256-GCM | ≥ 2 GB/s per core with AES-NI | microbenchmark |
| Shard PUT p99 | ≤ 150 ms (HDD), ≤ 25 ms (NVMe) | agent stats |
| `ResolvePlacement` | ≤ 15 ms p99 | coordinator |
| `ListObjectsV2` | ≤ 50 ms p99 at 10 M keys / bucket, 1000-key page | bench |
| Repair | 1 TiB of lost data reconstructed in ≤ 4 h | chaos |

---

## 6. Risk register

| # | Risk | Impact | Mitigation | Owner |
|---|---|---|---|---|
| R1 | Metadata store becomes the write bottleneck (one commit per PUT) | medium | batched commits per object; `synchronous_commit=off` on standby; partition by bucket; escape hatch = sharded metadata | Lead |
| R2 | Small-object amplification (60 shards × 128 B) | medium | small-object RC via SDP; v2 shard packing | Gateway |
| R3 | Geo repair saturates inter-site links | high | per-site token bucket, business-hours pause, prioritisation | Coordinator |
| R4 | Postgres failover = control-plane write outage | medium | Patroni + sync standby; gateway retry with jitter; documented degraded mode | Platform |
| R5 | Two-tier EC correctness (encode/decode with mixed failure patterns) is subtle | high | exhaustive property tests over all failure combinations for small parameters (n+k ≤ 10), then scale | Lead |
| R6 | Reimplementing SigV4 correctly (streaming, presign, chunked) | high | lift the canonicalisation test corpus from aws-sdk-go; fuzz; conformance against aws-cli | Gateway |
| R7 | Scope creep into Cubbit's unsupported features | medium | the compat matrix is a *contract*; extensions are flags, default off | Lead |
| R8 | Operator/Ansible surface delays the first real deployment | medium | M7 is deliberately after the data plane works; dev mode covers early demos | Platform |

---

## 7. Decisions I need from you before writing code

| # | Question | My default if you don't care |
|---|---|---|
| Q1 | **First milestone demo goal:** single-node dev cluster (fast visual progress) or 3-site simulated cluster (proves the actual thesis)? | Start single-node (M0–M3), then 3-site (M4). Both, in that order. |
| Q2 | **Metadata store:** PostgreSQL (production-grade, external dependency) or embedded-only (zero-dependency `fass all`)? | PostgreSQL primary + embedded journal store for dev mode (originally answered "SQLite"; superseded by D-C) |
| Q3 | **Scope of v1 S3 surface:** full matrix (adds ~8 d) or core CRUD+multipart+versioning first, lock/lifecycle/tagging in v1.1? | Full matrix, because "exactly reverse engineer it" implies the published surface |
| Q4 | **Zero-knowledge client SDK** in v1, or gateway-side crypto only (ZK deferred)? | Gateway-side crypto in v1; Go SDK with ZK as v1.1 |
| Q5 | **Platform target:** Kubernetes operator in v1, or systemd/compose only? | Compose + systemd in v1, operator in v1.1 |
| Q6 | **Licence and repo name** (`github.com/<org>/fass`) | MIT, `fass`, unless you say otherwise |
| Q7 | **Agent Teams:** do you want me to keep 2–3 teammates coding in parallel on the disjoint scopes in §3? | Yes — Gateway / Coordinator / Agent streams |

---

## 8. What "done" means for this design phase

- [x] Cubbit's public architecture reverse-engineered and cited (`01`)
- [x] Service decomposition + data flows + ADRs (`02`)
- [x] Chunking, two-tier EC, crypto, placement, repair, GC, durability math (`03`)
- [x] Per-service specs with ports, contracts, config, failure modes, SLOs (`04`)
- [x] S3 compatibility matrix including every deliberate divergence (`05`)
- [x] This plan: layout, milestones, test strategy, risks (`06`)
- [ ] **Your approval + answers to Q1–Q7**
- [ ] Then: `docs/schema.sql`, frozen protos, M0 bootstrap

No application code is written until this plan is approved — that was the explicit instruction, and it is also the right engineering call: the redundant-coding and placement design are where a wrong choice costs weeks.
