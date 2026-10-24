# FASS

**Geo-distributed, S3-compatible object storage in Go.** A from-scratch reimplementation of the
architecture behind [Cubbit DS3 Composer](https://docs.cubbit.io/composer/getting-started/what-is-ds3-composer),
reverse-engineered from public documentation and built to the same behavioural contract.

Objects are encrypted, split into chunks, encoded with **two-tier Reed–Solomon**, and scattered
across sites (Nexuses) and disks — so no single site, server, or disk can lose your data.

```
                     ┌─────────────────────────────┐
   S3 clients ──────►│  GATEWAY (stateless)        │
   SigV2/SigV4        │  S3 API · offloader · cache │──── shards (mTLS) ────┐
                     └──────────────┬──────────────┘                        │
                                    │ control (mTLS)                        ▼
                     ┌──────────────▼──────────────┐          ┌──────────────────────────┐
                     │  COORDINATOR (control plane)│          │  AGENTS (one per disk)   │
                     │  placement · metadata       │          │  immutable shards        │
                     │  membership · authz · repair│          │  repair · scrub          │
                     │  never sees data or keys    │          └──────────────────────────┘
                     └─────────────────────────────┘
```

## Quick start

```bash
git clone <repo> && cd fass
source scripts/env.sh          # workspace-local Go caches; deps are vendored
make build                     # bin/fass-{gateway,coordinator,agent,cli,console,bridge}

# A real 12-agent cluster across 3 simulated Nexuses, then upload 14 MiB,
# kill an entire Nexus, and read the object back.
./scripts/smoke-cluster.sh --nexus-loss

# Or a containerised 12-agent stack with a smoke check
make dev
```

Talk to it with the tools you already have:

```bash
export AWS_ACCESS_KEY_ID=dev-access-key AWS_SECRET_ACCESS_KEY=dev-secret-key AWS_DEFAULT_REGION=eu-west-1
aws --endpoint-url http://127.0.0.1:7000 s3 ls
```

## What it does

| Capability | Notes |
|---|---|
| **Two-tier erasure coding** | `geo(n,k) × local(n,k)` across Nexuses and disks. Recommended `geo 2+1 / local 16+4` = 1.875× overhead, survives an entire site loss. Flat coding is `geo(1,0)`. |
| **Redundancy Classes, Rings, Nexuses** | Policy objects with `aag` anti-affinity; agents are per-disk; rings scale out without reshuffling. |
| **Geo-fencing & placement** | Hard constraints (Nexus diversity, AAG, capacity headroom) then a weighted scorer on uptime/load/bandwidth/reputation/latency. Deterministic and replayable. |
| **S3 API** | 42 operations (exactly Cubbit's published supported set): bucket/object CRUD, multipart, versioning (UUIDv4 + S3 `null` for suspended), object lock (GOVERNANCE/COMPLIANCE/legal hold), tagging, lifecycle, ACLs, presigned URLs, conditional writes, verified checksums. Unsupported operations answer `501`, matching Cubbit's published matrix. |
| **Encryption** | AES-256-GCM per chunk, per-object file keys wrapped by a tenant KEK; encrypt-then-code so repair never needs a key. The coordinator is cryptographically blind. |
| **Self-healing** | Local repair inside a Nexus, geo repair across Nexuses, scrubbing, GC by authoritative shard-set id, rebalance. |
| **Operations** | `fass` CLI, HTMX console, Prometheus/OTel, Helm chart, systemd units, dev bootstrap. |
| **Migration** | `fass-bridge`: S3→FASS mover with verified read-back before source delete, plus an S3 proxy so clients can switch endpoints before migration finishes. |

## Verification

Nothing here is asserted without an executable gate:

```bash
make test                        # unit + integration, both storage backends
make e2e                         # 3-Nexus cluster; SIGKILL a whole Nexus, object still reads
make compat                      # S3 conformance rules against a live cluster (21 tests)
go test -tags=ha  ./test/ha/     # real primary crash + promotion: measured RTO/RPO
go test -tags=load ./test/load/  # mixed workload, contention storm, bloat/deadlock gates
./scripts/compat.sh              # stock aws-cli, rclone, s3cmd against the real API
COMPAT_TLS=1 ./scripts/compat.sh # same matrix over mTLS
```

Measured on a single dev box (not a capacity claim, but the order of magnitude is real):

| | |
|---|---|
| Failover | **489 ms** RTO, **RPO 0/20** acknowledged objects, restore 506 ms |
| Commit path | **−82%** p50 (309 → 56 ms) after replacing a global lock with native sequences and shared locks |
| PUT throughput | **+70%** (72 → 123 ops/s for 4 KiB objects) from those two fixes |
| Clients | aws-cli, rclone, s3cmd pass in plaintext, data-plane mTLS, and every-hop TLS with a custom CA |

## Design documentation

The reasoning lives in [`docs/`](docs/README.md):

| Doc | Contents |
|---|---|
| [01 — Reverse-engineering Cubbit](docs/01-reverse-engineering.md) | What Cubbit actually built, with sources; what we replicate and what is unknowable |
| [02 — Architecture](docs/02-architecture.md) | Control vs data plane, flows, consistency, failure domains, ADRs |
| [03 — Data plane](docs/03-data-plane.md) | Chunking, two-tier Reed–Solomon, key hierarchy, placement, repair, durability math |
| [04 — Services](docs/04-services.md) | Per-service contracts, ports, config, failure modes, SLOs |
| [05 — S3 API](docs/05-s3-api.md) | The compatibility matrix and every deliberate divergence |
| [06 — Delivery plan](docs/06-delivery-plan.md) | Milestones, scope decisions, test strategy, risks |
| [07 — Wire API](docs/07-wire-api.md) | Internal HTTP contract between the services |
| [08 — Operations](docs/08-operations.md) | Runbooks: TLS, agent config, bridge, troubleshooting |
| [09 — Deployment](docs/09-deployment.md) | Sizing from a Redundancy Class, upgrade order, measured HA/load numbers |

## Known gaps

Stated plainly rather than implied:

- **Dev metadata backend is not SQLite.** The approved design change (D-C in [docs/06](docs/06-delivery-plan.md))
  replaced it with a dependency-free embedded journal store behind the same repository interface: dev mode
  keeps the zero-dependency `fass all` story without vendoring a ~40 MB SQLite driver, and it is explicitly
  dev-grade rather than pretending to production durability.
- **KMIP/KMS** is not implemented — the tenant key seed is supplied as a hex value and its custody is manual.
- **Console auth** is a single Basic credential (no RBAC/OIDC/sessions) and is documented as dev-grade.
- **Kubernetes operator** (`cmd/fass-operator`) is not implemented; the Helm chart covers deployment.
- HA/load evidence comes from single-host drills: no multi-site failover, no long-running soak, no PITR-to-timestamp.

## Licence

MIT (see `LICENSE` if present; otherwise treat as MIT for this exercise).
