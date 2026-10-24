# Load test — PostgreSQL adapter (reference run #1)

Command (starts and cleans up its own PostgreSQL container, coordinator, 12 agents
and 2 gateways):

```bash
go test -tags=load -count=1 ./test/load/ -v -timeout 15m
```

Reference run: `2026-10-24T13:27Z`, macOS-class dev box (`host=… cpus=20`,
docker `postgres:16`, Go load generator, 15 GB RAM, ~5–6.5 GB free at start).
Machine spec, every phase, and the Postgres samples are in
[`results/run-20261024T132716Z.json`](results/run-20261024T132716Z.json).

Topology: `postgres:16` (`shared_buffers=256MB`, `max_connections=200`,
`autovacuum_naptime=5s`) → coordinator on PostgreSQL → 12 dev-bootstrap agents
(D′ RC, real shard I/O) → **2 gateways** sharing one deterministic key seed.
Workload: 20 s warmup + **60 s measured** mixed phase (32 PUT / 16 GET /
8 list / 4 version-churn workers), then a 200-way single-key contention storm,
then 10 s read-only. 12 MiB objects use single PUT via `pkg/sdk` (multipart is
covered by `test/compat`, not this profile).

## Measured (mixed, 60 s window)

| op | n | errors | p50 | p95 | p99 | max | rate |
|---|---:|---:|---:|---:|---:|---:|---:|
| PUT | 2 856 | 0 | 662 ms | 863 ms | **958 ms** | 1 169 ms | **47.6 ops/s** (10.9 MiB/s) |
| GET | 18 897 | 0 | 44 ms | 96 ms | **168 ms** | 499 ms | **315 ops/s** (66.5 MiB/s) |
| ListObjectsV2 (page+continuation) | 1 022 | 0 | 342 ms | 503 ms | **588 ms** | 720 ms | 17 ops/s |
| ListObjectVersions (coordinator API) | 975 | 0 | 120 ms | 183 ms | **228 ms** | 300 ms | 16 ops/s |
| version churn (PUT+DELETE marker) | 1 878 | 0 | 122 ms | 216 ms | **259 ms** | 371 ms | 31 ops/s |

Read-only phase (16 GET workers, 10 s): **690 ops/s, p99 109 ms** (mixed GET p99
168 ms) — reads are not the bottleneck.

Run-to-run variance on this shared machine is real: an earlier run of the same
profile measured 79 PUT/s / p99 1 072 ms and 498 GET/s / p99 142 ms. Treat these
as the ceiling order of magnitude, not an SLO.

## Contention storm (200 concurrent PUTs to one key)

| metric | value |
|---|---|
| wall time | 614 ms |
| p99 | 604 ms |
| errors | 0 |
| PostgreSQL deadlocks | **0** (before and after) |
| max `wait_event_type='Lock'` sessions | **39** (pool = 40) |

Interpretation: same-key commits **serialize** (expected: one transaction owns the
latest row via `FOR UPDATE`), but the waiter count is bounded by the connection
pool rather than exploding, throughput degrades roughly linearly with concurrency,
and the deadlock count does **not** grow with load. That is the "serialized by
design, not a convoy" signature; a convoy would show waiters ≫ pool size and/or
deadlocks/retries climbing with concurrency.

## Pool, bloat, correctness gates

| gate | result |
|---|---|
| PostgreSQL connections observed | max **41** of `max_connections=200` (pool 40 + sampler): no pool exhaustion |
| `kv` dead tuples | baseline 33 → peak **963** → final **17** after autovacuum (`autovacuum_naptime=5s`): reclaimed |
| PUT→GET verification (200 sampled keys, full SHA-256) | **200/200 byte-identical, 0 mismatches** |
| non-retryable 5xx | **0** (503-retryable: 0, 4xx: 0) |
| repair/scrub interference | none (`/v1/repair/status` unrecoverable = 0) |
| free memory during run | min 2.8 GB; 2 gateways kept (boot 6.5 GB free) |

## Findings / next

1. **Writes are latency-bound by the data path, not by the adapter.** PUT p99 is
   ~1 s while GET p99 is ~168 ms and read-only reaches ~690 GET/s; the commit
   transaction itself is not the limiting factor at this scale.
2. **Listing is the slowest control operation** (p99 0.6 s S3 list, 0.23 s
   coordinator version list) at only ~17 list/s per gateway pair. Worth profiling
   before calling the adapter done: it decodes every live version record in the
   prefix range. Not a correctness issue; a ceiling issue.
3. **No lock-convoy or deadlock signal.** Contention produced 0 deadlocks and a
   waiter count capped by the pool — the lock-order discipline held under 200-way
   pressure on one key.
4. **Bloat is real and reclaimed**, but the measured churn volume was modest
   (peak 963 dead tuples). A longer churn phase is needed to test autovacuum under
   sustained tombstone pressure, not to prove reclamation.
5. **Two client-side network errors** appeared on GET in an earlier run (no
   server 5xx); they were not reproducible in the reference run. Watch this in
   future runs — a rising network-error rate would point at connection churn
   between gateways and the SDK client, not at the metadata adapter.

## HA under load (not implemented here)

The harness is one step away: run the `test/ha` crash/promote sequence while this
workload is running and record the client error/latency spike during the
measured 456–482 ms failover window. That would close "gateway-level failover
behaviour" and "load" together; deliberately out of scope for task-17.
