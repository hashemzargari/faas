# 03 — Data Plane Specification

Chunking, two-tier erasure coding, cryptography, placement, repair, garbage collection, and the durability math that ties them together.

---

## 1. Object → chunk → shard: the storage hierarchy

```
Object (arbitrary size, 0 … 5 TiB)
  └─ Chunk            fixed size, ChunkSize = 16 MiB default        ← minimum unit of redundancy
      └─ Geo group    geo_n + geo_k groups, one per Nexus            ← geo-tier RS
          └─ Shard    local_n + local_k shards, one per Agent        ← local-tier RS
```

**Total shards per chunk** = `(geo_n + geo_k) × (local_n + local_k)`.
**Shard payload size** = `chunk_len / (geo_n × local_n)` (plus ≤ a few dozen padding bytes).
**Storage overhead** = the RC `ratio` (§2.4).

Worked example (the recommended 3-site RC, `geo 2+1`, `local 16+4`):

| Property | Value |
|---|---|
| Chunk | 16 MiB |
| Geo groups | 3 (2 data + 1 parity), one per Nexus |
| Shards per geo group | 20 (16 data + 4 parity) |
| Total shards per chunk | 60 |
| Shard size | 16 MiB / (2 × 16) = 512 KiB |
| Minimum shards to read | 32, from **2 different Nexuses** |
| Overhead | 60 / 32 = 1.875× |
| Blast radius survived | 1 whole Nexus + 2 servers per surviving Nexus |

### 1.1 Padding is negligible — small objects do **not** pay chunk-size padding
Encoding is exact-length: pad the ciphertext up to a multiple of `geo_n`, then each geo piece up to a multiple of `local_n`. Total padding ≤ `(geo_n−1) + (geo_n+geo_k)(local_n−1)` bytes — **59 bytes** for the RC above, regardless of object size. A 1 KiB object produces 60 shards of ~1 KiB, not 60 shards of 512 KiB.

The real small-object cost is **per-shard framing overhead**: each shard carries a ~128 B header (magic, codec params, checksums, ids). A 1 KiB object ⇒ ~8 KiB of shard bytes for 1 KiB of user data. Mitigations, in order:
1. **Small-object Redundancy Class** — route sub-256 KiB objects (Cubbit's published minimum billable size) to a cheap RC such as `local 4+2, geo 1+0` (6 shards ⇒ 6×128 B ≈ 768 B framing). This is exactly what Cubbit's Smart Data Placement "Small Files Optimization" example does.
2. **v2: shard packing** — group many small objects' shards into pack files (log-structured), one index entry per object. Deferred; documented as a known limitation.

### 1.2 Chunk sizing
| Object size | Chunks | Notes |
|---|---|---|
| 0 B | 0 | zero-byte object = metadata only, no shards |
| 1 B – 16 MiB | 1 | exact-length encoding, no padding waste |
| 16 MiB – 5 TiB | ⌈size/16 MiB⌉ | last chunk short |

`ChunkSize` is per-Redundancy-Class (4 / 8 / 16 / 32 / 64 MiB). Constraints: `ChunkSize % (geo_n × local_n) == 0` and shard size ≥ 4 KiB. Default 16 MiB.

### 1.3 Memory model (bounded, no unbounded buffering)
Per in-flight chunk on a gateway:
`ChunkSize` (ciphertext) + `ChunkSize × (geo_n+geo_k)/geo_n` (geo pieces) + `ChunkSize × ratio` (all shards) ≈ 16 + 24 + 30 = **70 MiB** worst case.
Gateway default `offloader.max_concurrent_chunks = 16` ⇒ ≈ 1.1 GiB heap; configurable, validated at boot. Multipart parts are chunked independently, so memory is independent of part size.

---

## 2. Two-tier Reed–Solomon

### 2.1 Pipeline (per chunk, on the gateway/offloader)

```
plaintext chunk
   │ 1. encrypt  → ciphertext (AES-256-GCM, framed per 1 MiB)
   │ 2. outer RS  → geo_n data + geo_k parity pieces          RS(geo_n, geo_k)
   │ 3. inner RS  → each piece → local_n + local_k shards     RS(local_n, local_k)
   │ 4. dispatch  → shard → agent endpoint (QUIC), parallel with per-agent concurrency cap
   ▼
checksums[] + placements[] → metadata commit
```

Read is the exact inverse, in reverse (inner decode per geo group in parallel → outer decode as soon as `geo_n` groups complete).

### 2.2 Parameter constraints (validated at RC creation)

| Constraint | Reason |
|---|---|
| `1 ≤ geo_n ≤ 16`, `0 ≤ geo_k ≤ 8` | outer code is small; `geo_n` bounded by Nexus count |
| `2 ≤ local_n ≤ 64`, `0 ≤ local_k ≤ 32` | inner code carries the bulk |
| `geo_n + geo_k ≤ 16`, `local_n + local_k ≤ 64` | fits GF(2⁸) (≤ 255) with margin for future |
| `1 ≤ aag ≤ local_n + local_k` | anti-affinity must allow a feasible packing |
| ring agents ≥ `local_n + local_k` per Nexus | feasibility |
| `geo_n + geo_k ≤ #eligible Nexuses` | feasibility + geo-fencing |
| `ChunkSize % (geo_n·local_n) == 0` | exact shard sizing |
| ratio ≤ 4.0 | refuse pathological configs |

`geo(1,0)` degenerates to a flat single-tier code — that is how we express Cubbit DS3-Cloud's flat `20+40` (`geo 1+0`, `local 20+40`, ratio 3.0).

### 2.3 Shard identity and on-disk layout (Agent)

```
shard_id = base32( BLAKE2b-256( shard_set_id ‖ geo_group ‖ local_index )[:16] )

/data/
  shards/ab/cd/<shardid>.shard      # header + payload, immutable
  index/pebble/                     # shard_id → (set, group, idx, len, checksum, created, expires)
  incoming/<uuid>.partial           # write temp; fsync; rename → shards/
```

Shard header (little-endian, ~128 B): `magic "FASSSHD1" | version | codec_params(geo_n,geo_k,local_n,local_k) | chunk_index | geo_group | local_index | shard_set_id(16) | plaintext_len | payload_len | checksum(32) | created_at`.

Design consequences:
* **Self-describing shards.** A repairer can decode a chunk from 20 shards plus one header — it does not need the object manifest. This is what makes blind repair and disaster recovery tractable.
* **Immutable payload.** No WAL for shard bytes. A crash leaves `.partial` files, which are swept on boot.
* **Per-disk agent.** One agent owns one disk; the disk is the failure and the accounting unit (matches Cubbit's per-disk agent model, 1 thread + 1–2 GB RSS per disk).

### 2.4 Where each parameter lives

| Parameter | Stored in | Mutable? |
|---|---|---|
| RC tuple | `redundancy_classes` (control plane) | no — new RC for changes |
| Ring ↔ RC binding | `rings` | no — new ring to grow/change |
| Per-object RC id | object manifest | no (per object lifetime) |
| Codec params (copy) | shard header + manifest | no |
| Placement | `shard_sets.placement` + displacements | yes — CAS on generation |

---

## 3. Cryptography

### 3.1 Key hierarchy

```
Tenant Key Seed (32 B, per tenant)
   │  HKDF-SHA256(seed, info="fass/kek/v1", salt=tenant_id)
   ▼
Tenant KEK (AES-256)
   │  wraps
   ▼
File Key (32 B, random per object *version*)  ──HKDF──> Per-chunk key (info="fass/chunk/v1", salt=chunk_idx)
                                                       │
                                                       ▼
                                              AES-256-GCM frames
```

* **File key**: random per object version, never derived from content (no convergent-encryption leak of equality).
* **Wrapped file key** is stored in the object manifest — the Coordinator holds ciphertext only.
* **Chunk key** = `HKDF(file_key, salt=chunk_index, info="fass/chunk/v1")` ⇒ unique key per chunk, no nonce reuse risk across chunks.
* **Version id ordering:** the *gateway* generates the version id (UUIDv4) **before** encrypting, and passes it to `CommitObject`. That is what lets the AAD bind to it. It also makes a retried commit idempotent. Version ids are opaque to clients, so gateway assignment is invisible.
* **Frames**: chunk is split into 1 MiB frames; each frame `AES-256-GCM(frame_key(nonce=random 96-bit || frame_idx), AAD = tenant‖bucket‖key‖version_id‖chunk_idx‖frame_idx‖plaintext_frame_len)`. AAD binds ciphertext to its exact location — a shard moved to another object/chunk fails authentication, which defeats substitution attacks by a malicious agent.
* **Nonces**: 96-bit random per frame (collision probability negligible at 2³² frames/key); frame index in AAD prevents reorder/truncation.

### 3.2 Encryption modes (mirrors Cubbit's three modes + zero-knowledge)

| Mode | Key source | Gateway holds key? | Coordinator holds seed? | Use |
|---|---|---|---|---|
| `single-key` | one 32 B key in gateway config/Secret | yes | no | dev, single-tenant |
| `local-multi-keys` | per-tenant keys in gateway Secret file | yes | no | air-gapped small deployments |
| `remote-multi-keys` | gateway **polls Coordinator** for tenant config; fallback **KMIP 1.4** for private tenants | yes (transient) | yes for public tenants; no for `zero_knowledge: true` | production |
| `zero-knowledge` | SDK/client holds seed; gateway is a dumb proxy | **no** | no | regulated tenants |

`update_period` default `1h`; a gateway with the wrong keys must fail loudly (HTTP 500 on the affected object) rather than silently corrupt — Cubbit documents the same failure mode and warns objects become permanently unreadable if KMS state is lost. We add: **key fingerprint in the manifest** so a mismatch is detected at read time with a precise error, not a GCM auth failure.

### 3.3 KMIP integration
KMIP 1.4 over mTLS: one Managed Object of type *Secret Data* per tenant, `Name` = tenant UUID. Operations used: `Get` (seed), `Create` (provisioning), `Rotate` (v2). Local cache with TTL + negative cache; circuit breaker so a KMS outage does not cascade into gateway thread exhaustion.

### 3.4 Rotation
`WrapKeyVersion` in the manifest. Rotation re-wraps file keys (cheap, metadata-only) — **no payload rewrite**. Payload re-encryption is an explicit, rate-limited background job for compliance scenarios only.

### 3.5 What each party can see

| Party | Plaintext | File key | Wrapped key | Shards | Placement |
|---|---|---|---|---|---|
| Client (non-ZK) | yes | no | no | no | no |
| Client (ZK) | yes | yes | yes (client-side) | no | no |
| Gateway | transiently | transiently | yes | transiently | yes |
| Coordinator | **no** | **no** | yes (ciphertext) | **no** | yes |
| Agent | **no** | **no** | no | yes | local only |
| Repairer | **no** | **no** | no | yes | yes (job scope) |

The invariant that makes the whole design work: **encrypt-then-code**, so Reed–Solomon inversion never needs a key.

---

## 4. Placement engine

### 4.1 Inputs
`shard_set_id`, `rc`, candidate rings, topology snapshot `{nexus → node → agent}` with per-agent `{state, free_bytes, load_ewma, bw_headroom, uptime_score, reputation, rtt_class}`, tenant `geo_fence` (allowed Nexus ids), and `aag`.

### 4.2 Hard constraints (filters — a candidate failing any is dropped)
1. Agent `ACTIVE`, disk healthy, not `DECOMMISSIONING`.
2. `free_bytes ≥ needed × headroom` (`headroom = 1.15`).
3. Nexus ∈ tenant geo-fence (and ∈ RC's Nexus set).
4. One shard per Agent per shard-set (no self-duplication).
5. ≤ `aag` shards of the same shard-set per Node.
6. Ring capacity available (`ring.used + needed ≤ ring.capacity`).
7. Agent not in a Nexus currently flagged `DEGRADED` for writes.

### 4.3 Scoring (soft, weighted — the published five axes)
```
score(a) = 0.25·uptime(a)            # EWMA availability over 30 d
         + 0.25·(1 − load(a))        # shards×bytes / free capacity
         + 0.15·bw_headroom(a)       # NIC utilisation headroom
         + 0.15·reputation(a)        # penalises nightly-offline / churn history
         + 0.10·free_capacity(a)     # prefer emptier disks (balance)
         + 0.10·rtt_score(a)         # measured RTT class to the requesting gateway
```
Then a **greedy max-min diversity pass** when filling slots:
```
effective(a) = score(a) × Π_i (1 − proximity(a, chosen_i))
proximity = 1.0 same agent · 0.6 same node · 0.2 same rack · 0.05 same nexus(already excluded)
```
Geo group selection first (choose `geo_n+geo_k` distinct Nexuses maximising the same diversity objective at Nexus level, plus capacity balance), then local slots within each Nexus.

**Determinism:** ties broken by `HMAC-SHA256(shard_set_id, agent_id)`. Same topology + same shard set ⇒ same placement, which makes placement reproducible in tests and debuggable in incidents. Re-randomising on retry is allowed but logged as a *displacement*.

### 4.4 Displacement (the failure path)
If a shard PUT fails or times out (default 5 s, 2 retries): mark the agent suspect for this set, take the next-best candidate, and record `displacement{slot, original_agent, actual_agent, generation}`. Metadata stores the authoritative slot→agent map for the current generation. Displacements are the *only* per-chunk variability in placement — without them, placement is a pure function.

### 4.5 Why not store 60 rows per chunk in SQL
At 16 MiB chunks, 1 TiB = 65 536 chunks × 60 slots = 3.9 M placement rows per TiB — untenable. Instead:
* `shard_sets(id, rc_id, ring_id, generation, placement_hash, displacement_blob)` — one row per chunk.
* The *base* placement is recomputed deterministically from `(ring_id, epoch, shard_set_id)` rather than stored.
* `displacement_blob` (varint delta-encoded, usually empty) stores only repairs/replacements.
Per-TiB metadata ≈ 65 536 rows + a few hundred bytes of checksums each (truncated BLAKE2b-64: 60×8 = 480 B ⇒ ~31 MiB/TiB). Documented as the scale-out path; v1 may store explicit placements behind the same interface (`PlacementStore`) for simplicity.

### 4.6 Rings and capacity
A Ring is a bounded set of Agents implementing one RC. When a Ring's used capacity exceeds **85%**, the Coordinator stops placing into it and (if new Nodes were registered) creates a new Ring for the same RC — matching Cubbit's "when a Ring nears capacity, a new Ring can be created for the same Redundancy Class". Agents may belong to multiple Rings (multi-tenancy / tiering / isolation), which is how a single disk serves a hot RC and a cold RC.

---

## 5. Repair subsystem

### 5.1 Detection
Two independent signals, both cheap:
1. **Membership**: agent heartbeat lost ⇒ `SUSPECT` after 3 misses (15 s), `OFFLINE` after 60 s.
2. **Inventory diff**: agents report a shard inventory digest every 5 min; Coordinator compares against expected slots.

A shard is *lost* when its agent is `OFFLINE` beyond `repair_grace` (default 10 min — absorbs reboots) or reports it corrupt/missing.

### 5.2 Thresholds (Cubbit-compatible, per tier)
```
healthy_local_shards(group) < local_n + ⌊local_k/2⌋   → LOCAL repair
reachable_nexus_groups        < geo_n + ⌊geo_k/2⌋     → GEO repair
```
With flat `20+40` this is exactly Cubbit's published `n + k/2 = 50`.

### 5.3 Job types

| Job | Actor | Reads | Writes | Key needed |
|---|---|---|---|---|
| **Local repair** | an Agent in the same Nexus | `local_n` shards from peers in Nexus (P2P) | missing `local_*` slots | **no** |
| **Geo repair** | a Gateway (or a designated repair agent with cross-site access) | `geo_n` groups × `local_n` shards | the lost Nexus's `local_n+local_k` shards into a replacement Nexus | **no** |
| **Corruption repair** | same as local/geo | shards minus the corrupt one | replacement shard | **no** |
| **Rebalance** | Agent (copy) | existing shard bytes | identical shard bytes on a new agent | n/a — byte copy, no decode |

> Local repair is intra-Nexus and cheap (Cubbit: "minimizing bandwidth usage and optimizing recovery speed"). Geo repair crosses sites and is the expensive path — it is bandwidth-scheduled separately (default 200 Mbit/s per site, configurable) and can be paused during business hours.

### 5.4 Scheduling and safety
* Job lease 10 min, idempotent, at-most 2 concurrent per source agent, global queue ordered by `deficit_ratio × object_size^0.5 × tenant_priority`.
* **CAS commit**: after the repairer writes replacement shards it calls `CommitRepair(shard_set_id, expected_generation)`; if generation moved (another repair won), it discards its work — shards are immutable and unreferenced, so GC collects them. No locks, no lost updates.
* Repair storm control: cluster-wide repair bandwidth budget; if exceeded, repairs queue rather than saturate the inter-site links.
* Anti-entropy: nightly Merkle-root comparison per agent shard range; mismatch ⇒ targeted scrub ⇒ repair (detects silent corruption heartbeat cannot see).

### 5.5 Scrub
Agent-side rolling scrub: verify each shard's checksum at least every 7 days, rate-limited (default 50 MiB/s per disk, only when idle). Any mismatch is reported to the Coordinator as `CORRUPT` → repair from peers. This is the mechanism that turns "bit rot" into a repairable event rather than a read error.

---

## 6. Garbage collection, deletion, rebalance

| Path | Trigger | Grace | Notes |
|---|---|---|---|
| Aborted upload | `upload_session` expiry (default 7 d) | — | orphan shards from failed PUTs |
| Overwrite (unversioned) | after commit of the new version | 24 h | allows in-flight readers to finish |
| Version delete | `DeleteObject?versionId` | 24 h | blocked while retention/legal hold active |
| Delete marker | non-current version sweep | 24 h | |
| Multipart abort | session expiry | 7 d | |
| Repair loser | CAS conflict | 1 h | immutable orphan |
| Bucket delete | bucket is empty of objects **and versions** | — | matches Cubbit's documented requirement |

Deletion is **metadata-first, shard-second**, and never the reverse: a shard is only deleted after no manifest generation references it. The GC worker drains `deletion_queue` in batches with a per-agent rate limit so GC never competes with repair.

**Rebalance** is byte-copy only (no decode/encode, no key): used for (a) filling a new Ring, (b) draining a `DECOMMISSIONING` agent, (c) capacity balancing. Rule: a shard move is chosen only when the destination's free-capacity score improves by > 10%; moves are throttled and cancellable.

---

## 7. Durability and availability — the numbers

### 7.1 Availability of an object vs. per-node availability (independent failures)
`P(unavailable) = Σ_{j=0}^{n−1} C(N,j)·p^j·(1−p)^(N−j)`, where `N = n+k` (flat view), `p` = per-node availability.

| Code | Overhead | p=0.99 | p=0.95 | p=0.90 | p=0.80 |
|---|---|---|---|---|---|
| 4+8 | 3.0× | 2.1e-16 | 3.7e-10 | 1.7e-07 | 6.2e-05 |
| 6+12 | 3.0× | 8.2e-23 | 8.3e-14 | 5.3e-10 | 2.5e-06 |
| 10+20 | 3.0× | 1.3e-35 | 4.4e-21 | 5.8e-15 | 4.5e-09 |
| 12+24 | 3.0× | 5.4e-42 | 1.0e-24 | 2.0e-17 | 1.9e-10 |
| **20+40** | 3.0× | **1.7e-67** | **3.6e-39** | 2.9e-27 | 7.3e-16 |
| 20+10 | 1.5× | 4.6e-15 | 1.1e-07 | 8.9e-05 | 2.6e-02 |
| 10+10 | 2.0× | 1.6e-17 | 5.4e-10 | 7.1e-07 | 5.6e-04 |
| 8+4 | 1.5× | 7.5e-08 | 1.8e-04 | 4.3e-03 | 7.3e-02 |

**This table is the argument for wide codes.** At an 80% per-node availability — realistic for consumer-grade or spot infrastructure — `20+40` still yields 7.3e-16 unavailability while `8+4` collapses to 7%. Cubbit's flat 20/60 exists precisely because its cloud nodes are unreliable and uncontrolled. In a Composer deployment with real data-centre nodes (p ≈ 0.999), a narrow hierarchical code is economically correct: `2+1 × 16+4` at 1.875× and p=0.999 gives unavailability ≈ 10⁻²¹ with far less raw capacity.

### 7.2 Durability (probability of permanent object loss)
`P(loss) = Σ_{j=n}^{N} C(N,j)·q^j·(1−q)^(N−j)`, `q` = probability a node is lost permanently during the exposure window.

| Code | q=1% | q=5% | q=10% |
|---|---|---|---|
| 4+8 | 4.6e-06 | 2.2e-03 | 2.6e-02 |
| 10+20 | 2.5e-13 | 1.2e-06 | 4.5e-04 |
| 20+40 | 2.9e-25 | 5.7e-12 | 7.8e-07 |

**The 11-nines target is not a property of the code alone — it is a property of the code plus MTTR.** Durability is governed by the probability that ≥ `n+1` failures accumulate *before repair completes*. Therefore the design fixes hard operational invariants:

| Invariant | Target | Enforced by |
|---|---|---|
| Repair start latency | < 10 min after detection | repair scheduler SLO |
| Repair completion (≤ 1 TiB of affected data) | < 4 h | bandwidth budget + parallelism |
| Max concurrent unrepaired losses | ≤ `k/2` per shard set | repair priority escalates to P0 |
| Scrub coverage | 7 d | agent scrubber |
| Correlated-failure guard | geo tier spans ≥ 2 Nexuses, AAG caps per-node | hard placement constraints |

We will **measure** rather than assert: a chaos suite (`07-testing`) kills agents/nodes/Nexuses and reports the observed object-loss rate and repair MTTR against these targets.

### 7.3 Correlated failures are the real risk
Independent-failure math flatters any code. The model above assumes failures are independent; real ones are not (power, rack, firmware bug, operator error). Mitigations are structural, not mathematical:
* geo tier always spans distinct Nexuses; AAG limits shards per server;
* Nexus membership is declared by an operator, never inferred, so a shared PDU is never treated as independent;
* `geo_k ≥ 1` for any multi-site RC;
* tenant geo-fencing prevents "3 Nexuses" that are actually 3 racks in one DC.
