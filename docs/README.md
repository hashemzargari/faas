# FASS — a Go reimplementation of Cubbit DS3 Composer

> Geo-distributed, S3-compatible object storage: objects are encrypted, split into chunks, encoded with **two-tier Reed–Solomon**, and scattered across Nexuses (sites/AZs) and disks — so no single site, server, or disk can lose your data.

**Status: implemented and verified.** The design below was approved before coding and then built;
see the root [`README.md`](../README.md) for the current state, quick start and verification gates.
The documents in this directory are kept as the design record — including the decisions that were
later revised (ADR-3b on the metadata store shape, the dev topology arithmetic) — because the
reasoning is part of the deliverable.

---

## Read this in order

| Doc | What it answers |
|---|---|
| [01 — Reverse-engineering Cubbit](01-reverse-engineering.md) | What Cubbit DS3 actually is (two products, two redundancy models), the published entity model (Swarm/Nexus/Node/Agent/Ring/Redundancy Class), the encryption and placement facts, and exactly what we replicate vs. what is unknowable |
| [02 — High-level architecture](02-architecture.md) | Control plane vs data plane, component inventory, write/read/repair sequence diagrams, consistency model, failure domains, ADRs, tech choices |
| [03 — Data plane specification](03-data-plane.md) | Chunking, hierarchical erasure coding, key hierarchy and AES-256-GCM framing, the placement engine, repair/scrub/GC/rebalance, and the durability math |
| [04 — Service specifications](04-services.md) | Every service: contracts, ports, config, state, failure modes, SLOs — Gateway, Coordinator (6 sub-services), Agent, Cache, Key service, Console, CLI, Bridge, Operator |
| [05 — S3 API specification](05-s3-api.md) | The full compatibility matrix (42 supported / 55 not), header-by-header behaviour, versioning/object-lock/ACL/tagging/lifecycle semantics, limits, errors, and the seven deliberate divergences |
| [06 — Delivery plan](06-delivery-plan.md) | Repo layout, milestones M0–M8 with exit criteria, parallel workstreams, test strategy, performance targets, risks, and the decisions taken (kept as the record, including superseded ones) |
| [07 — Wire API](07-wire-api.md) | The internal HTTP contract between gateway, coordinator and agents |
| [08 — Operations](08-operations.md) | Runbooks: TLS/PKI and rotation, agent config, bridge operations, `/healthz` posture checks, troubleshooting |
| [09 — Deployment](09-deployment.md) | Sizing a Redundancy Class, install/upgrade/rollback order, measured HA and load numbers, known operational gaps |
| [10 — Record codec](10-record-codec.md) | Proposal only, deliberately not implemented: versioned binary metadata records with a measured do-not-ship-unless bar |
| [Known issues](KNOWN_ISSUES.md) | The confidence record: fixed defects with evidence, open issues, and what is explicitly **not** validated |

Supporting research: [Cubbit DS3 API report](research/cubbit-ds3-api-report.md) · [Cubbit DS3 Composer architecture report](research/cubbit-ds3-composer-report.md)

---

## The design in one screen

```
                       ┌─────────────────────────────┐
   S3 clients ────────►│  GATEWAY (stateless)        │
   SigV2/SigV4         │  S3 frontend + offloader    │──── shards (QUIC/mTLS) ────┐
                       └──────────────┬──────────────┘                            │
                                      │ control (gRPC)                            ▼
                       ┌──────────────▼──────────────┐              ┌──────────────────────────┐
                       │  COORDINATOR (control plane)│              │  AGENTS (1 per disk)     │
                       │  placement · metadata       │              │  immutable shards · scrub │
                       │  membership · auth · repair │              │  local repair (P2P)      │
                       │  NEVER sees data or keys    │              └──────────────────────────┘
                       └─────────────────────────────┘
```

**Data path:** object → 16 MiB chunks → AES-256-GCM (per-chunk key from a per-object file key) → outer RS(geo_n, geo_k) across Nexuses → inner RS(local_n, local_k) across disks → shards on agents.

**Why two tiers:** a single flat code can't exploit the structure of real failure domains. `geo 2+1 × local 16+4` gives **1.875× overhead while surviving an entire site loss**; a flat code needs 3× to approach that. Cubbit's DS3 Cloud uses flat `20+40` precisely because its nodes are unreliable consumer devices — our RedundancyClass abstraction expresses *both* (flat = `geo 1+0`).

**The one property everything hangs on:** *encrypt-then-code*. Reed–Solomon inversion works on ciphertext, so repairers, agents, and the Coordinator never need a key. The Coordinator is cryptographically blind; agents only ever hold ciphertext shards.

---

## Design at a glance

| Question | Designed | As built |
|---|---|---|
| Language | Go 1.24+ (Cubbit's own gateway binary is `gods3`) | Go 1.25 (`go.mod`), stdlib-first, two vendored dependencies (`klauspost/reedsolomon`, `jackc/pgx`) |
| Shard transport | QUIC + mTLS, one stream per shard | **HTTP/1.1 over TLS 1.3 with mTLS**; the contract is transport-agnostic so QUIC can replace it (docs/07) |
| Control transport | gRPC/protobuf | **HTTP + JSON** against frozen wire types in `internal/contract` (schema-regression tested) |
| Erasure coding | `klauspost/reedsolomon`, GF(2⁸), two tiers | same — `internal/ec`, geo × local, flat = `geo(1,0)` |
| Metadata | PostgreSQL primary + sync standby | PostgreSQL as a transactional KV store (ADR-3b); a dependency-free embedded journal store for dev mode — **not SQLite** (D-C) |
| Encryption | AES-256-GCM framed at 1 MiB, HKDF per-chunk keys, envelope-wrapped file keys, KMIP 1.4 | AES-256-GCM framed at 1 MiB, HKDF-SHA256 per-chunk keys, envelope-wrapped file keys. **KMIP is not implemented** — the tenant seed is supplied as a hex value with manual custody |
| Default redundancy | `geo 2+1`, `local 16+4`, `aag 2` ⇒ 1.875× overhead, survives 1 site | same; the dev cluster uses `geo 2+1 / local 3+1` with 6 MiB chunks because a 2-agent-per-Nexus topology cannot satisfy the production RC |
| S3 surface | 42 operations supported, 55 explicitly `501` — the Cubbit-published matrix | same, and set-verified operation-by-operation against Cubbit's published table |
| Durability target | 11 nines **given** repair MTTR ≤ 4 h (the code alone doesn't give you this — the ops loop does) | unchanged as a target; see [KNOWN_ISSUES](KNOWN_ISSUES.md) for what is and is not validated |

---

## How to read the plan's honesty

* **Cited:** everything about Cubbit's architecture is traceable to a public doc URL in [01 §7](01-reverse-engineering.md).
* **Inferred:** anything not published is marked `INFERRED` (their ML placement model, wire protocol, NAT traversal).
* **Designed by us:** the placement scorer, consistency contract, schema, and SLOs are our engineering choices, stated as such.
* **Deliberately better than Cubbit:** we verify checksums, implement conditional writes, support presigned URLs, and reject SSE-C instead of silently ignoring it — with a `cubbit-strict` mode to reproduce their exact behaviour for conformance testing ([05 §9](05-s3-api.md)).

---

## Current state

The plan above is implemented and gated (see the root [README](../README.md) for commands and
measured numbers, and [KNOWN_ISSUES](KNOWN_ISSUES.md) for the honest confidence record). This
directory is deliberately kept as the **design record**: decisions that were later revised —
ADR-3b's transactional-KV metadata shape, the dev topology arithmetic, the QUIC/gRPC transport
choices, the SQLite dev mode — remain visible with their outcomes noted, because "what we
planned and why we changed it" is part of the deliverable.
