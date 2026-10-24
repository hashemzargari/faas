# Load test — PostgreSQL adapter: ceiling and write-path attribution

```bash
go test -tags=load -count=1 ./test/load/ -v -timeout 15m   # or: make load
```

Disposable topology per run: `postgres:16` (`shared_buffers=256MB`,
`max_connections=200`, `autovacuum_naptime=5s`) → coordinator on PostgreSQL →
12 dev agents (D′ RC, real shard I/O) → **2 gateways** sharing one deterministic
key seed. Workload: 20 s warmup + **60 s measured** mixed phase (32 PUT /
16 GET / 8 list / 4 version-churn workers), then a 200-way single-key contention
storm, a 10 s read-only phase, and three 4 KiB PUT diagnostic phases. Artifacts:
[`results/run-20261024T133436Z.json`](results/run-20261024T133436Z.json) (latest,
with commit attribution), plus the earlier run without diagnostics.

Reference machine: shared dev box, 20 CPUs, 16 GB RAM (~6 GB free at boot, min
2.4 GB during the run). Run-to-run variance on this box is ±2×; treat the numbers
as the **measured ceiling**, not an SLO.

## Mixed phase by payload class

| op | n | p50 | p95 | p99 | throughput |
|---|---:|---:|---:|---:|---:|
| PUT 4 KiB | 2 509 | 659 ms | 886 ms | 1 415 ms | 42 ops/s |
| PUT 1 MiB | 280 | 687 ms | 907 ms | 998 ms | 4.7 ops/s (4.7 MiB/s) |
| PUT 12 MiB | 30 | 880 ms | 1 055 ms | 1 232 ms | 0.5 ops/s (6.0 MiB/s) |
| GET | 18 263 | 45 ms | 106 ms | 207 ms | 304 ops/s (65 MiB/s) |
| ListObjectsV2 (paged) | 930 | 380 ms | 532 ms | 917 ms | 15.5 ops/s |
| version listing (coordinator API) | 889 | 129 ms | 192 ms | 296 ms | 15 ops/s |
| churn (PUT + DELETE marker) | 1 830 | 125 ms | 224 ms | 282 ms | 30 ops/s |
| read-only GET phase | 7 580 | 18 ms | 39 ms | 81 ms | 758 ops/s |

The median is dominated by 4 KiB PUTs, and the payload size barely moves it
(4 KiB 659 ms vs 1 MiB 687 ms vs 12 MiB 880 ms): the cost is per request, not per
byte. That is the write-amplification symptom (12–24 shard writes for a 4 KiB
object), **but the next section shows the shard writes are not where the time
goes.**

## Attribution: coordinator commit, not disk fsync

| phase | p50 | source |
|---|---:|---|
| coordinator `/v1/placement` | **32 ms** | coordinator request log |
| coordinator `/v1/objects:commit` | **523 ms** | coordinator request log |
| agent shard PUT (handler wall time, includes fsync+rename+dir fsync) | **0.31 ms** (p95 2.3, p99 5.7, max 27.7) | agent request logs |
| client PUT total | 663 ms | client |
| remainder = EC encode + shard wave + gateway overhead | **108 ms (16%)** | derived |

62 shard writes/s per agent is nowhere near the agent's capacity; the shard wave
is ~16% of PUT latency. **The earlier fsync-bound-shards hypothesis is refuted by
this data — do not optimize the agents first.**

Diagnostic phases (4 KiB single PUTs, same gateways/agents) separate service time
from shared-row contention:

| scenario | PUT p50 | coordinator commit p50 |
|---|---:|---:|
| 1 writer (no contention) | **6.4 ms** | **2.0 ms** |
| 16 writers, same bucket | 45 ms | — |
| 16 writers, 16 buckets | 26 ms | **14.8 ms** |

Commit service time is ~2 ms. It grows ~7× across 16 writers **even with several
buckets**, so the contention is not only the bucket row: the commit transaction
also serializes on a single global version-sequence counter row (`nextSeq`), and
it takes `FOR UPDATE` locks for reads that do not need them (bucket metadata,
version-id lookup). At the mixed phase's 60 concurrent workers the commit p50 is
523 ms, beyond what the 16-writer diagnostic predicts — the remaining gap needs
statement-level/adapter timing before it is fully attributed (do not guess).

## Gates

| gate | result |
|---|---|
| PUT→GET verification (200 sampled keys, SHA-256) | **200/200 byte-identical** |
| non-retryable 5xx | **0** (retryable 503: 0, 4xx: 0) |
| PostgreSQL connections | max **42** / 200; no pool exhaustion |
| contention storm (200 concurrent PUTs, one key) | 617 ms wall, p99 608 ms, **0 deadlocks**, max 38 lock waiters (pool 40) |
| `kv` dead tuples | 21 → 867 peak → **171** after autovacuum (reclaimed) |
| repair/scrub interference | none (`unrecoverable` = 0) |

## Fix candidates, expected-value order (not implemented)

1. **Remove the global version-sequence counter lock** from the commit transaction
   (per-key sequence, DB sequence, or order by latest record). The multi-bucket
   diagnostic still shows 7× contention with zero bucket sharing.
2. **Drop `FOR UPDATE` from read-only reads** in the commit path (bucket metadata,
   version-id idempotency lookup); only the latest row needs the lock.
3. **Fewer DB round trips per commit** (batch version + latest + manifest + seq
   writes).
4. Agent-side fsync batching is **not** justified by this data. Small-object RC
   routing (SDP) may help capacity/cost, not this latency.

## Not shown here

Long/sustained churn (bloat over hours), degraded disks/WAN latency, failover
under load. The next drill is HA-under-load: combine this harness with
`test/ha`'s crash/promote and measure the client spike across the 456–482 ms
failover window.

## Fix 1 measurement — native PostgreSQL sequences (2026-10-24)

Change: `nextSeq` now goes through a backend `NextSequence`; PostgreSQL uses
native `fass_version_seq`/`fass_deletion_seq` (`nextval`, lock-free, migration
0002) instead of a shared `kv` counter row read with `FOR UPDATE`. Embedded keeps
its transaction-local counter row (behaviour unchanged). Correctness guard added
to the parity suite: after N concurrent commits to one key, exactly one latest,
strictly unique sequence values, and the highest sequence is the latest version;
it passes on both backends.

Same load profile, before → after:

| metric | before | after fix 1 | delta |
|---|---:|---:|---:|
| coordinator commit p50 | 309 ms | **242 ms** | −22% |
| 4 KiB PUT p50 | 389 ms | **317 ms** | −19% |
| 4 KiB PUT throughput | 72 ops/s | **84 ops/s** | +17% |
| 1 MiB PUT p50 | 413 ms | **346 ms** | −16% |
| multi-bucket 16-writer commit p50 | 11.4 ms | **6.1 ms** | −46% |
| `tx_begin_pool_acquire` avg | 4.2 ms | 3.6 ms | ≈ |
| `kv_get_for_update` avg (63k–60k calls) | 32.0 ms | **31.8 ms** | unchanged |
| read-only GET | 1 115 ops/s | **1 269 ops/s** | +14% |

Gates unchanged: 200/200 byte-identical, 0 non-retryable 5xx, 0 deadlocks, bloat
reclaimed, `make build/vet/test`, e2e and `test/compat` green.

**Interpretation:** the global sequence row was ~22% of commit latency, but the
dominant term is still `kv_get_for_update` (~32 ms average across ~60k
acquisitions), i.e. the remaining `FOR UPDATE` reads in write transactions
(bucket row, latest row, version-id lookup) queue behind each other. Fix 2
(plain reads for read-only inputs; lock only the latest row) is still on the
critical path — do not stop at fix 1.

## Fix 2 measurement — shared bucket locks (2026-10-24)

Change: commit-path bucket metadata reads use a **shared** row lock (`FOR SHARE`)
instead of exclusive `FOR UPDATE`. Concurrent commits no longer queue on the
bucket row, while bucket deletion (exclusive `FOR UPDATE`) still serialises
against in-flight commits — so the delete-vs-commit race is closed without
serialising writers. Version-id idempotency read was left locked: with the KV
upsert exposing no unique-violation, an unlocked read would let two concurrent
retries both write; making it safe needs a `PutIfAbsent` + retry path (deferred,
noted).

Same profile, cumulative:

| metric | baseline | fix 1 | fix 2 | vs baseline |
|---|---:|---:|---:|---:|
| coordinator commit p50 | 309 ms | 242 ms | **56 ms** | −82% |
| 4 KiB PUT p50 | 389 ms | 317 ms | **148 ms** | −62% |
| 4 KiB PUT throughput | 72 ops/s | 84 | **123 ops/s** | +70% |
| 1 MiB PUT p50 | 413 ms | 346 | **188 ms** | −54% |
| `kv_get_for_update` avg | 31.8 ms | 31.8 | **14.2 ms** | −55% |
| `tx_begin_pool_acquire` avg | 4.2 ms | 3.6 | 3.6 | ≈ |
| contention (200 same-key PUTs) | 617 ms | 900 | 1 002 ms | same-key lock unchanged |

Gates: 200/200 byte-identical, 0 non-retryable 5xx, 0 deadlocks, bloat reclaimed
(48 → 1 018 → 38), max 45/200 DB connections. **Most of the commit latency is
gone; stop here rather than doing fix 3.** Remaining work as separate tickets:
`kv_scan_range` is now the second-worst statement (29 ms avg; listing p99 was
already weakest), the client saw 8 transient network errors (no server 5xx), and
JSON encode/decode CPU is the next structural cost (binary record codec proposal).
