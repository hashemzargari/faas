# FASS

**Geo-distributed, S3-compatible object storage in Go.** A from-scratch reimplementation of the
architecture behind [Cubbit DS3 Composer](https://docs.cubbit.io/composer/getting-started/what-is-ds3-composer),
reverse-engineered from public documentation and built to the same behavioural contract.

Objects are encrypted, split into chunks, encoded with **two-tier Reed–Solomon**, and scattered
across sites (Nexuses) and disks — so no single site, server, or disk can lose your data.

> ### Maturity: stable development release — **not production-validated**
>
> The feature surface is complete and every capability below is backed by an executable gate.
> What is **not** true: that this is battle-tested. All HA, chaos and load evidence comes from
> single-host drills with simulated sites; there is no multi-site soak, no real Kubernetes
> installation, and no independent security review. See
> [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md) for the per-item confidence record. Use it to
> learn from, evaluate, or build on — not to store data you cannot lose yet.

```
                     ┌─────────────────────────────┐
   S3 clients ──────►│  GATEWAY (stateless)        │
   SigV4 / presigned  │  S3 API · offloader · cache │──── shards (mTLS) ────┐
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
source scripts/env.sh        # workspace-local Go caches; dependencies are vendored
make build                   # bin/fass-{gateway,coordinator,agent,cli,console,bridge}

# A real 12-agent cluster across 3 simulated Nexuses: write 14 MiB, kill an
# entire Nexus, read the object back.
./scripts/smoke-cluster.sh --nexus-loss

# Or the containerised 12-agent stack with a smoke check
make dev
```

Then use the clients you already have:

```bash
export AWS_ACCESS_KEY_ID=dev-access-key AWS_SECRET_ACCESS_KEY=dev-secret-key AWS_DEFAULT_REGION=eu-west-1
aws --endpoint-url http://127.0.0.1:7000 s3 ls
```

## What it does

| Capability | Notes |
|---|---|
| **Two-tier erasure coding** | `geo(n,k) × local(n,k)` across Nexuses and disks. Recommended `geo 2+1 / local 16+4` = 1.875× overhead, survives loss of an entire site. A flat scheme is `geo(1,0)`. |
| **Redundancy Classes, Rings, Nexuses** | Policy objects with `aag` anti-affinity; one agent per disk; rings scale out without reshuffling. |
| **Smart Data Placement** | Hard constraints (site diversity, AAG, headroom) then a weighted scorer over uptime/load/bandwidth/latency/reputation; deterministic and replayable. |
| **S3 API** | **42 operations** — Cubbit's exact published supported set, verified operation-by-operation against their table: bucket/object CRUD, multipart, versioning (UUIDv4, S3 `null` for suspended), object lock (GOVERNANCE/COMPLIANCE/legal hold), tagging, lifecycle, ACLs, presigned URLs, conditional writes, checksums. The remaining 55 published operations answer `501`, matching Cubbit. |
| **Encryption** | AES-256-GCM per chunk; per-object file keys wrapped by a tenant KEK; **encrypt-then-code**, so repair never needs a key and the coordinator is cryptographically blind. |
| **Self-healing** | Local repair inside a Nexus, geo repair across Nexuses, scrubbing, GC by authoritative shard-set identity, rebalance. |
| **Operations** | `fass` CLI, HTMX console, Prometheus metrics, Helm chart, systemd units, dev bootstrap. |
| **Migration** | `fass-bridge`: an S3→FASS mover (verified read-back before the source copy is deleted) **plus an S3 proxy**, so clients can be switched to the new endpoint before migration finishes. |

## Security model

- **Fail-closed by default.** Coordinator, gateway and agents refuse to start without TLS material
  unless `--insecure`/`--dev` is passed explicitly; those flags warn on every start and are
  reported in `/healthz` (`security.insecure=true`).
- **mTLS between components**, TLS 1.3, certificates hot-reloaded in-process before expiry with no
  restart. Plaintext is all-or-nothing — there is no per-hop "insecure" switch.
- **Encrypt-then-code**: the control plane stores ciphertext and never receives file keys or
  plaintext; repair and scrub operate on shards without keys.
- **Auth**: SigV4 (+ presigned URLs), four-stage authorisation (IAM deny → bucket policy → ACL →
  object-lock guard), CRN-scoped resources.
- **Not done:** no external security review, no fuzzing campaign, no HSM/KMIP (tenant key seed is
  provided as a hex value and its custody is manual), console has a single credential and no
  RBAC/OIDC.

## Deployment modes

| Mode | How | Status |
|---|---|---|
| Single-host dev | `make dev` (docker compose: coordinator, 12 agents, gateway) | verified |
| No-container dev | `./scripts/smoke-cluster.sh [--nexus-loss]` | verified |
| Systemd hosts | `deploy/systemd/` units + env examples | rendering/`systemd-analyze` verified; not installed on real hosts |
| Kubernetes | `deploy/helm/fass/` chart (TLS on by default, existing Secrets only) | `helm lint`/`template` + flag audit verified (58 rendered env names, 0 unknown); **never installed on a cluster** |
| 3-site production | coordinator on PostgreSQL + one agent per disk per Nexus + stateless gateways | design and single-host drill only; multi-site not validated |

## Verification

Nothing below is asserted without a command you can run. The full audit, including what is
*not* validated, is in [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).

```bash
make test                                  # unit + integration, both storage backends
go test -race ./internal/gateway/... ./internal/agent/...
go test -tags=compat ./test/compat/        # 22 S3 conformance rules, live cluster
go test -tags=e2e ./test/e2e/              # 3 Nexuses; SIGKILL a whole Nexus, object still reads
go test -tags=ha ./test/ha/                # real primary crash + promotion + restore
TMPDIR=$PWD/.dev/loadtmp go test -tags=load ./test/load/   # load + contention correctness gates
./scripts/compat.sh                        # stock aws-cli, rclone, s3cmd
COMPAT_TLS=1 ./scripts/compat.sh           # fleet mTLS
COMPAT_CONTROL_TLS=1 COMPAT_EDGE_TLS=1 ./scripts/compat.sh  # every hop + HTTPS S3 edge
./scripts/smoke-cluster.sh --nexus-loss    # 12-agent cluster with a destroyed Nexus
make deploy-lint && make dev
```

### What is verified vs. merely implemented

| Claim | Verified how |
|---|---|
| Writes survive loss of a whole site | `test/e2e`: kill a Nexus mid-life, read back byte-identical |
| Coordinator failover | `test/ha`: crash primary, promote, 489 ms RTO / RPO 0-of-20 |
| S3 semantics (versioning, lock, lifecycle, ACL, listing, multipart) | 22 conformance rules + 3 third-party clients |
| 42-operation matrix equals Cubbit's published set | set-diff of Cubbit's table against the gateway's operation table |
| Data-plane + control-plane + S3-edge encryption | three executable compat modes with real clients |
| No silent data corruption on read under load | load gate: byte-identical verification corpus + a byte-count/checksum rejection gate |
| No truncated success responses | prefix-buffered GET + abort counters + regression tests |
| Metadata integrity under concurrency | parity suite: one `is_latest`, unique sequences, no lost version |

Measured on a single shared dev box — **order-of-magnitude evidence, not capacity planning**:

| | |
|---|---|
| Failover | 489 ms RTO, RPO 0/20 acknowledged objects, restore 506 ms |
| Commit path | p50 309 → 56 ms (−82%) after removing a global lock and adopting native sequences |
| PUT throughput | 72 → 123 ops/s for 4 KiB objects at 60-way concurrency |
| GET under load | 0 non-retryable 5xx across 3 consecutive 2-minute runs; 200/200 sampled reads byte-identical |
| Clients | aws-cli, rclone, s3cmd pass in plaintext, fleet mTLS, and every-hop TLS with a custom CA |

## Design documentation

| Doc | Contents |
|---|---|
| [01 — Reverse-engineering Cubbit](docs/01-reverse-engineering.md) | What Cubbit built, with sources; what we replicate and what is unknowable |
| [02 — Architecture](docs/02-architecture.md) | Control vs data plane, flows, consistency, failure domains, ADRs |
| [03 — Data plane](docs/03-data-plane.md) | Chunking, two-tier Reed–Solomon, key hierarchy, placement, repair, durability math |
| [04 — Services](docs/04-services.md) | Per-service contracts, ports, config, failure modes |
| [05 — S3 API](docs/05-s3-api.md) | The 42/55 compatibility matrix and every deliberate divergence |
| [06 — Delivery plan](docs/06-delivery-plan.md) | Milestones, scope decisions (including superseded ones), test strategy |
| [07 — Wire API](docs/07-wire-api.md) | Internal HTTP contract between services |
| [08 — Operations](docs/08-operations.md) | Runbooks: TLS/PKI, agent config, bridge, posture checks, troubleshooting |
| [09 — Deployment](docs/09-deployment.md) | Sizing from a Redundancy Class, upgrade order, measured HA/load numbers |
| [10 — Record codec](docs/10-record-codec.md) | Proposal only, with an explicit do-not-ship-unless bar |
| [Known issues](docs/KNOWN_ISSUES.md) | Every fixed defect with its evidence, open issues, and what is **not** validated |

## Known limitations

- **Not production-validated:** single-host evidence only; no multi-site soak, no PITR-to-timestamp, no independent security audit.
- **The dev metadata backend is a dependency-free embedded journal store, not SQLite** (approved deviation D-C): dev-grade durability only, and never a production system of record.
- **No KMIP/KMS**, no HSM integration; tenant key custody is manual.
- **Console** has one static credential, no RBAC/OIDC, and no multi-tenant scoping.
- **No Kubernetes operator** — deployment is a chart (rendering-verified, never installed on a cluster).
- **Bridge** listings show the source while a migration is in progress (`listing_source` is exposed in the API); no merged pagination.
- Several loud, explicitly-labelled `--insecure`/`--dev` plaintext escape hatches remain for development.

Full detail, including the defects found and how, is in [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).

## Licence

MIT.
