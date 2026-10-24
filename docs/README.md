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
| [06 — Delivery plan](06-delivery-plan.md) | Repo layout, milestones M0–M8 with exit criteria, parallel workstreams, test strategy, performance targets, risks, and the questions I need answered |

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

| Question | Answer |
|---|---|
| Language | Go 1.24+ (Cubbit's own gateway binary is `gods3`) |
| Shard transport | QUIC + mTLS, one stream per shard |
| Control transport | gRPC/protobuf |
| Erasure coding | `klauspost/reedsolomon`, GF(2⁸), two tiers |
| Metadata | PostgreSQL primary + sync standby (SQLite for dev mode) |
| Encryption | AES-256-GCM framed at 1 MiB, HKDF per-chunk keys, envelope-wrapped file keys, KMIP 1.4 |
| Default redundancy | `geo 2+1`, `local 16+4`, `aag 2` ⇒ 1.875× overhead, survives 1 site |
| S3 surface | 42 operations supported, 55 explicitly `501` — the Cubbit-published matrix |
| Durability target | 11 nines **given** repair MTTR ≤ 4 h (the code alone doesn't give you this — the ops loop does) |

---

## How to read the plan's honesty

* **Cited:** everything about Cubbit's architecture is traceable to a public doc URL in [01 §7](01-reverse-engineering.md).
* **Inferred:** anything not published is marked `INFERRED` (their ML placement model, wire protocol, NAT traversal).
* **Designed by us:** the placement scorer, consistency contract, schema, and SLOs are our engineering choices, stated as such.
* **Deliberately better than Cubbit:** we verify checksums, implement conditional writes, support presigned URLs, and reject SSE-C instead of silently ignoring it — with a `cubbit-strict` mode to reproduce their exact behaviour for conformance testing ([05 §9](05-s3-api.md)).

---

## Next step

Approve [06 §7 questions](06-delivery-plan.md) (Q1–Q7), then the first commit is M0: module skeleton, frozen protos, `docker compose up` with one coordinator, one gateway, six agents, and a green CI — followed immediately by the single-tier object path (M3) so there is something demonstrable early.
