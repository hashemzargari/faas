# 10 — Binary metadata record codec (proposal, not implemented)

Status: **proposal only**. Do not implement until the listing bounded-projection
work is measured; if `LIMIT` pushdown removes most of the JSONB cost, this codec
may not be worth its compatibility risk.

## Problem
ADR-3b stores each metadata record as JSONB. The load profile attributes ~23% of
coordinator CPU to `encoding/json/v2` map/string encode/decode (JSONB round trip
per statement). This cost is paid on every commit and on every listing row, and
because it happens **inside** the latest-row critical section it also lengthens
lock hold time and therefore throughput.

## Encoding
```
value = codec_tag (1 byte) || payload
  0x00  legacy JSON document (all existing rows; unchanged bytes)
  0x01  binary codec v1
```
Binary v1: length-prefixed field table, little-endian integers, no map
allocations for known record types; schema/version is part of the codec tag, not
inside the payload. Record types are the same Go structs; only the marshal path
changes.

## Rollout (reader-first, no mixed-version hazard)
1. Reader release: adapter decodes tags 0x00 and 0x01. Writers still emit 0x00.
2. Soak/soak-rollback window; old coordinators cannot read 0x01, so writers must
   not flip until every coordinator is on the reader release.
3. Writer release behind `--db-binary-codec` (default off): emit 0x01 for new
   writes only. Old rows keep 0x00 indefinitely (no rewrite required).
4. Optional background re-encode job, rate-limited, for hot rows; gaps are fine,
   both representations stay readable.
5. Rollback: flip the flag off; readers remain dual.

Constraints: the `storage` interface is unchanged; KV spaces/keys are unchanged;
the schema-drift test is extended with a second decoder so a struct field cannot
be added without updating both codecs.

## Measurement plan (same profile as `test/load/REPORT.md`)
- Baseline: current run with `--db-debug-timings` + pprof.
- After each stage (reader dual, writer flip) re-run the identical profile and
  report: commit p50/p99, 4 KiB PUT throughput, listing p99, `kv_get_for_update`
  and `kv_put`/`kv_get` averages, coordinator CPU pprof JSON share.
- Success bar: measurable latency or CPU win at equal correctness gates (200/200
  PUT→GET identical, 0 non-retryable 5xx, 0 deadlocks, bloat reclaimed). If the
  win is <10%, stop and keep JSON: compatibility risk is not worth it.

## Risks
- Mixed-version fleets: reader-first order is mandatory.
- Debuggability drops (rows no longer human-readable without a tool); provide a
  `fass coordinator dump-record` helper before flipping the writer.
- Drift-test bypass: the second decoder must be mandatory in CI, not optional.
