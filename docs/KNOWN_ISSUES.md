# Known issues, fixed defects and unvalidated areas

This document is the honest defect and confidence record for FASS at the
stabilisation freeze. It exists because a green test suite says only that the
tests we thought of pass — not that the system is production-validated.

**Status vocabulary used throughout**

| Status | Meaning |
|---|---|
| **FIXED** | Reproduced, root-caused, fixed, and covered by a regression test or an executable gate. The commit is named. |
| **OPEN** | Known, understood, not fixed. Either non-blocking by design or explicitly deferred. |
| **NOT VALIDATED** | No evidence either way. Do not read absence of a bug report as absence of a bug. |

Severity: **S1** data loss / corruption / silent wrong answer · **S2** operation
fails or is unavailable · **S3** degraded, confusing or operational risk only.

---

## 1. OPEN issues (none release-blocking)

### O-1 · Bridge listings during migration show the source only — S3
A bucket under migration lists from the **source** until the migration
completes. Objects written to the target after the migration started may not
appear in listings until `completed`. Visibility is explicit, not implied:
`GET /v1/bridges/{id}` returns `listing_source: "source"`, and every listing
response carries `x-fass-bridge-listing: source`. Merged pagination across
two stores is deliberately not implemented.
**Workaround:** treat `completed` as the point at which listings are
authoritative for the target; do not run a delete-driven sync against a bucket
whose bridge is still `in-progress`.

### O-2 · Console authentication is single-credential — S2 (deployment)
One Basic/static credential, no RBAC, no OIDC, no per-tenant scoping, no
sessions. The console is documented as a dev-grade operator surface; TLS and
client certificates are supported, human browser client-cert UX is poor.
**Workaround:** run the console behind an authenticating proxy, or leave it
disabled in production (the Helm chart supports `console.enabled=false`).

### O-3 · KMIP/KMS key custody is manual — S2 (operational)
The tenant key seed is supplied as a hex value from a file/flag. There is no
KMIP client, no HSM integration, no automatic wrapping-key rotation.
**Workaround:** custody the seed in a secret manager and rotate by re-wrapping
tenant KEKs; this is a documented manual procedure, not an automated one.

### O-4 · No Kubernetes operator — S3
`cmd/fass-operator` is empty. Deployment is a Helm chart (rendering and
flag-acceptance validated; see NOT VALIDATED) plus systemd units. There is no
CRD reconciliation, no self-healing of pods, no rolling-upgrade orchestrator.

### O-5 · Loud plaintext escape hatches exist — S3 (by design)
`--insecure` / `--dev` / `FASS_*_INSECURE` permit plaintext listeners for
development. They warn on every start, are reported in `/healthz`
(`security.insecure=true`), and the console shows a persistent banner.
`--coordinator-insecure` was **removed** (per-hop plaintext no longer exists);
it survives only as a deprecated console alias for one release. The risk is
deliberate and visible, not accidental.

### O-6 · Dev metadata backend is not crash-durable in the PostgreSQL sense — S3
The embedded journal store used by `fass all` / dev mode is dependency-free and
dev-grade: it is not a substitute for the PostgreSQL system of record, has
narrower durability and recovery semantics, and must not back production data.
See deviation D-C in [06-delivery-plan.md](06-delivery-plan.md).

---

## 2. FIXED defects (with evidence)

Every entry below was found by an external instrument — a real client, a
conformance rule, a chaos drill, a load profile or a live migration — not by
re-reading our own code. That pattern is the main quality signal in this
release.

### F-1 · Reads returned "not enough shards" while every agent served 200 — S1
**Symptom** (load gate): `offloader: not enough shards available: chunk 0: 0/3
geo groups reconstructible, need 2`, 6–12 per run, non-retryable 500s.
**Diagnosis:** agent logs showed 274,409/274,410 shard GETs returning 200 —
the shards were never missing. Root cause was a **race**: `fetchGroup` returned
as soon as quorum was reached without joining the hedged parity goroutines that
write into the same `out` slice, which `readChunk` then copied — a torn element
made `CanDecode` see a phantom missing group. A second path cancelled queued
data-shard fetches on `parityFinished`, dropping shards that were merely waiting
on the read semaphore.
**Fix:** always join both wait groups before returning/copying; cancel only after
the joins; bounded per-chunk retry with one manifest re-resolve; reason-labelled
shard diagnostics (`transport|status|read|size|checksum|info_checksum|ctx|
semaphore_drop`) and one attributable ERROR per unreconstructible chunk.
**Evidence:** `TestReadWithSingleReadSlotNeverDropsShards` (failed before the
fix, passes under `-race`); load harness now also fails on size/checksum
rejections while agents are healthy. Commit `3c1d182`. **Three consecutive
clean load-gate runs** on the final tree (`run-20261024T150949Z`,
`151203Z`, `151412Z`, plus a fourth with the shard-rejection gate live):
0 non-retryable 5xx, 0 retryable 503, 0 network errors, 200/200 sampled
verifications byte-identical, and `gets_ok=370160, error_ctx=1648,
error_read=13, checksum/size rejects=0` — i.e. the remaining shard-fetch
"errors" are benign post-quorum cancellations, not rejected data.

### F-2 · Failed GET streams emitted a truncated `200` — S1
**Symptom:** 4 × `unexpected EOF` client-side on GET under load, with **zero**
server-side 5xx. A backup tool would treat a short body as a completed file.
**Cause:** `handleGetObject` called `WriteHeader(200)` before streaming; any
shard/decode failure afterwards could not be retracted.
**Fix:** buffer a 64 KiB prefix before committing the response; failures inside
the window return the S3 XML error envelope with stale object headers removed.
Post-prefix truncation is unretractable over HTTP/1.1 and is now **counted**
(`s3_response_aborted_total{reason=offloader_read|client_write}`,
`fass_gateway_response_aborted_after_headers_total`) and logged with request id.
**Evidence:** `TestGetFailureWithinPrefixReturnsXMLError`,
`TestGetFailureAfterPrefixIsCounted`; 16-check client matrix unaffected.
Commit `079b712` (+ `9988712` for the counters).

### F-3 · `GET` of a zero-byte object returned `500` — S2
**Symptom:** every client failed to read empty objects; 5/50 objects in a live
bridge migration.
**Cause:** the coordinator stores no manifest blob when there are no chunks, so
an empty object's manifest carried a zero encryption envelope and the read path
tried to unwrap a 0-byte file key.
**Fix:** read short-circuits `size == 0`. **Coverage gap closed at three
levels:** regression test (`TestEmptyObjectReadsAsEmptyBody`), zero-byte round
trips with aws-cli and rclone in the client matrix, and a new conformance rule
covering PUT/HEAD/GET/Range-416/copy/list/delete of empty objects.
Commits `c4c8628`, `21ee781`, `92fa93e`.

### F-4 · Commit path serialised globally on a shared counter row — S2
**Symptom:** PUT p50 389 ms / 47.6 ops/s at 60-way concurrency; commit p50
309 ms against a measured raw commit capacity of >5,000/s.
**Cause:** `nextSeq` was a `kv` row read with `FOR UPDATE` in every commit, and
bucket metadata reads also took `FOR UPDATE`.
**Fix:** native PostgreSQL sequences for version/deletion ids (`nextval`,
migration 0002); bucket metadata reads take `FOR SHARE` (deletion keeps the
exclusive lock). Measured: commit p50 **309 → 56 ms (−82%)**, 4 KiB PUT p50
**389 → 148 ms (−62%)**, throughput **72 → 123 ops/s (+70%)**.
**Evidence:** parity suite asserts concurrent commits to one key yield exactly
one `is_latest`, unique sequences, highest-sequence-is-latest, no lost version;
load gates unchanged. Commits `cc9c199`, `ea5e311`.

### F-5 · Ring-usage accounting silently dropped under load — S2
**Symptom:** `WARN ring usage accounting failed … statement timeout (57014)`
under load, meaning capacity/usage numbers were quietly wrong.
**Cause:** a separate DB transaction per commit doing read-modify-write on the
shared `rings/<id>` row — the same serialization class as F-4, one layer away.
**Fix:** in-memory accumulation, 1 s batched flush, delta snapshot subtraction,
pending bytes retained on failure, explicit `dropped` counter.
**Evidence:** `TestRingUsageBatchedFlush`; a load run with the fix shows 0
ring-usage warnings and 0 statement timeouts. Commit `ef9e3f1`.

### F-6 · Listing read the whole key range — S2
**Symptom:** listing p99 588–922 ms; listing is the weakest control op and is
what `aws s3 ls`, rclone sync planning and backup tools do.
**Cause:** the adapter executed the full prefix range while Go stopped iterating
client-side; the DB transferred and JSONB-decoded every row.
**Fix:** optional `LimitedScanner` with `LIMIT bound+1`, falling back to the
unbounded scan when the bound is hit so pagination can never silently truncate;
embedded backend bounds its loop; `maxKeys*4+256` headroom for delimiter groups.
Measured 48.8 ms → 3.5 ms on a 20k-row range. SQL-side JSONB projection was
measured to be **slower** and was not adopted.
**Evidence:** bounded-visit test (657 of 5,000 keys for a page of 100), EXPLAIN
plan assertion, parity test for mid-group delimiter splits and
adds/deletes-between-pages; conformance 22/22. Commit `47c6b4e`.

### F-7 · Typed-nil scrubber panicked `/v1/stats` — S2
`--scrub=false` produced a typed-nil `*scrub.Scrubber` in a non-nil interface,
defeating the nil check; `GET /v1/stats` panicked. Found by the new agent TLS
end-to-end test. Panic logs now carry a stack. Commit `cc7c418`.

### F-8 · TLS hot reload served stale certificates — S1 (security)
`GetCertificate` is only consulted by Go when the ClientHello carries SNI or the
static `Certificates` list is empty; agents are dialled by IP (no SNI), so
"rotation" would have silently served the expiring certificate until it failed.
Found by the IP-based rotation test. Fix: serve exclusively through
`GetCertificate`, clear the static list, keep the previous certificate on a torn
file, and drive renewal from `pki.ShouldRenew` so components cannot disagree
about the renewal window. Commit `820cd7a` (+ `cc7c418`).

### F-9 · Health endpoint misreported during database outage — S2
`/healthz` returned 500 (indistinguishable from "objects are broken") when the
coordinator's database was down; connection failures also looked permanent to
callers. Fixes: `503` with `{"status":"unhealthy","database":"unreachable"}`,
`storage.ErrUnavailable` mapped to retryable 503. Found by the HA drill.
Commit `92342de`.

### F-10 · No TLS on the agent→coordinator hop — S1 (security)
A TLS-only coordinator stranded every agent, forcing `--coordinator-insecure` in
compat and docs. Fixed with `--coordinator-ca` / `--coordinator-server-name` /
`--coordinator-client-cert|-key` (distinct from shard-listener flags), fail-closed
on `https://` without a CA and on `http://` outside `--insecure`, actionable
mTLS errors, and live proof: coordinator TLS-only + `--require-mtls`, 12/12
agents over TLS, 14 MiB round trip byte-identical. The transitional flag was
then deleted from gateway and compat. Commits `1c8b5a6`, `642a150`.

### F-12 · Transient database pressure surfaced as non-retryable 500 — S2
**Symptom:** under load, `GET`/`ListObjectVersions` returned
`InternalError (500)` while the coordinator logged
`canceling statement due to statement timeout (SQLSTATE 57014)`.
**Cause:** only class-08 connectivity errors (and a few hand-listed codes) were
classified as transient; `57014` (statement/lock timeout) and class `40`
(serialization failure, deadlock) fell through to a permanent-looking 500, so
S3 clients had no reason to retry a briefly overloaded database.
**Fix:** those codes now map to `storage.ErrUnavailable` → `503` retryable, the
same path as other connectivity failures. This is a classification fix for a
transient dependency failure, **not** a reclassification of the read defect in
F-1, which was a genuine bug and is fixed. Commit `4b04267`.
**Residual:** repeated 503s still indicate an undersized or contended database;
they are recorded separately by the load gate and should be treated as an
operational capacity signal (see §4, performance context).

### F-13 · A stricter load gate that could never fire — S3 (verification)
The load harness added a "shards rejected on size/checksum while agents are
healthy" gate, but `summary.GatewayShards` was never assigned, so the gate
always read a nil map and silently passed. A gate that cannot fail is worse
than no gate. Now the gateway `/metrics` counters are scraped into the report
before the gate evaluates; first live run shows 0 size/checksum rejects.
Commit `9d1372e`.

### F-14 · Gateway shard counters were never exported — S3 (diagnostics)
The gateway created its metrics registry *after* constructing the offloader and
never passed it in, so `fass_gateway_shard_gets_total`,
`shard_get_errors_total{reason}`, `chunk_unreconstructible_total` and
`checksum_mismatch_total` were absent from `/metrics` (every load report printed
`gateway shard stats: map[]`), making the F-1 diagnostics unverifiable.
Registry hoisted and passed to both. Commit `4b04267`.

### F-11 · Multi-tenancy/Interop audit of the README and docs — S3
Repeatedly discovered documentation drift, each corrected with its reason
recorded rather than silently renumbered:
Cubbit's matrix is **42** supported / 55 unsupported, not 41/54 (`9295a1d`);
the dev backend is an embedded journal store, **not SQLite** (`e81fca1`);
there are **three** executable TLS fleet modes, not four, because agents are
all-or-nothing (`9988712`); a removed gateway env var was still rendered by the
Helm chart, caught by a mechanical rendered-env-vs-product-flags check.

---

## 3. Reliability incidents observed during development

These were failures of process or environment, not of the product. Recorded
because they shaped the verification discipline.

| Incident | Lesson applied |
|---|---|
| Scripted `sed`/Python patches silently no-op'd on gofmt-realigned text while `go build` passed; contract fields promised to peers failed to land twice | Use the edit tool (which errors on mismatch) and assert the change with a grep in the same command; verify structurally, never by build alone |
| 27 MB of ELF binaries were committed; the first fix re-added them | Remove and gitignore build outputs; commit with explicit paths, never `git add -A` |
| A commit was pushed with a red `go vet` because a `;` let the commit run after an `&&` chain broke | Never commit a red tree; `vet` and `test` are gates |
| Two agents patched the same harness files concurrently | Announce cross-cutting sweeps; split write scopes |
| A stale "four TLS modes" claim survived into a report | Correct claims explicitly when a later change invalidates them |
| The load gate failed for a timing reason (autovacuum window) | Extend the wait (60 s → 180 s) rather than weaken the assertion |
| A failed load gate reported only "6 non-retryable 5xx" with no cause | Harness now preserves service logs and prints error-bearing lines on failure |

---

## 4. NOT VALIDATED (explicit gaps)

Listed so that absence of evidence is not mistaken for evidence of correctness.

| Area | Status | What is missing |
|---|---|---|
| **Multi-site / WAN behaviour** | NOT VALIDATED | All HA and chaos work ran on a single host with 3 simulated Nexuses. No real inter-site latency, partition, or asymmetric failure testing. |
| **Soak / long-run stability** | NOT VALIDATED | Longest run is ~120 s (load). No hours-long soak, no slow leak detection, no growth-over-time analysis. |
| **PITR and backup/restore** | PARTIAL | Restore drill measured (dump → coordinator → read-back, ~430–510 ms). No PITR-to-timestamp, no off-host backup verification. |
| **Real Kubernetes install** | NOT VALIDATED | Chart is `helm lint`/`template` validated against the product's real flags (58 rendered env names, 0 unknown) but has never been installed on a cluster (no kind/minikube available here). |
| **Operator / CRD** | NOT IMPLEMENTED | `cmd/fass-operator` is empty (O-4). |
| **KMIP/KMS** | NOT IMPLEMENTED | Manual seed custody only (O-3). |
| **Independent security review** | NOT VALIDATED | No external audit, no penetration test, no fuzzing campaign. SigV4, ACL/policy evaluation, TLS posture and key handling are tested but not adversarially reviewed. |
| **Large objects / large buckets** | PARTIAL | Largest tested object 14 MiB; largest listing corpus 20k keys. No multi-GB single objects, no million-key bucket behaviour. |
| **Client ecosystem breadth** | PARTIAL | aws-cli, rclone and s3cmd are exercised in every mode. No boto3/Go-SDK/Java-SDK matrix, no S3-compatible appliances. |
| **Console under multi-tenant load** | NOT VALIDATED | Console is single-credential and untested above dev scale. |
| **Performance claims** | CONTEXT-BOUND | All numbers come from one shared dev box (±2× run-to-run variance observed). They are order-of-magnitude evidence, not capacity planning inputs. |
| **Load gate environment** | CAVEAT | The load profile writes several GB of shards; if `TMPDIR` is `/tmp` (tmpfs) that consumes RAM until agents stall and placement returns 507, producing a false failure (observed: one 9,021-5xx run). Run the gate with `TMPDIR` on a real filesystem — e.g. `TMPDIR=$PWD/.dev/loadtmp` — which is what the three clean runs used. |
| **Repair under load** | PARTIAL | Repair and scrub are covered by unit/integration tests and a live drill; not exercised while a load profile is running. |

---

## 5. Final verification pass (stabilisation freeze)

Run once on the frozen tree, sequentially (`scripts` bind fixed ports; the load gate needs a
disk-backed `TMPDIR`). Log: `.dev/verify-final.log` (gitignored, local).

| Command | Result | Notes / measurements |
|---|---|---|
| `go build ./...` | **PASS** | |
| `go vet ./...` | **PASS** | |
| `go test ./... -count=1` | **PASS** | 41 packages |
| `go test -race ./internal/gateway/...` | **PASS** | |
| `go test -race ./internal/agent/...` | **PASS** | |
| `go test -tags=compat ./test/compat/` | **PASS** | 22 rules |
| `go test -tags=e2e ./test/e2e/` | **PASS** | 8.5 s, whole-Nexus SIGKILL, byte-identical read-back |
| `go test -tags=ha ./test/ha/` | **PASS** | 3.9 s; RTO ~489 ms, RPO 0/20, restore ~430–510 ms |
| `TMPDIR=$PWD/.dev/loadtmp go test -tags=load ./test/load/` | **PASS ×3 consecutive** | 123–138 s each; 0 non-retryable 5xx, 0 retryable 503, 0 network errors; 200/200 sampled reads byte-identical; 0 size/checksum shard rejects |
| `./scripts/compat.sh` | **PASS** | aws-cli, rclone (incl. tree sync + hashes), s3cmd |
| `COMPAT_TLS=1 ./scripts/compat.sh` | **PASS** | fleet mTLS (agents + gateway + coordinator) |
| `COMPAT_CONTROL_TLS=1 COMPAT_EDGE_TLS=1 ./scripts/compat.sh` | **PASS** | every hop TLS + HTTPS S3 edge with custom CA |
| `./scripts/smoke-cluster.sh --nexus-loss` | **PASS** | 12 agents, 14 MiB byte-identical with one Nexus destroyed |
| `make deploy-lint` | **PASS** | Helm lint/template for all values files + systemd verify |
| `make dev` | **PASS with workaround** | 12/12 agents, byte-identical round trip. **Environment limitation:** needs `DOCKER_CONFIG=$PWD/.dev/docker-config` because buildx cannot write to the default `~/.docker` in this sandbox (documented in docs/08 troubleshooting) |
| DS3 Bridge live migration (2 clusters, 50 objects) | **PASS on 2026-10-24** (not re-run in this pass) | `migrated=50 failed=0`, target byte-identical, source empty; proxy mode tested over TLS. The scratch harness was not committed, so this is a historical run, not a repeatable gate — unit tests cover the semantics |
| Real `helm install` | **NOT RUN** | no cluster available in this environment |
| Multi-site / WAN failover | **NOT RUN** | single-host drills only (§4) |
| Soak / long-running | **NOT RUN** | longest exercise is ~2 min (§4) |
| Independent security review | **NOT RUN** | (§4) |

Known residual risks after this pass: transient database pressure returns `503` (retryable, by
design) rather than success — repeated 503s are a capacity signal, not a bug; and the load gate
must not be run with `TMPDIR` on tmpfs (§4, load-gate environment caveat).

## 6. Where the evidence lives

| Gate | Command |
|---|---|
| Unit/integration (both storage backends) | `make test` |
| Race-sensitive packages | `go test -race ./internal/gateway/... ./internal/agent/...` |
| S3 conformance (22 rules) | `go test -tags=compat ./test/compat/` |
| Whole-Nexus loss, encryption, geo rebuild | `go test -tags=e2e ./test/e2e/` |
| Real failover + restore | `go test -tags=ha ./test/ha/` |
| Load correctness gates | `go test -tags=load ./test/load/` |
| Third-party clients, plaintext | `./scripts/compat.sh` |
| Third-party clients, fleet mTLS | `COMPAT_TLS=1 ./scripts/compat.sh` |
| Third-party clients, every hop + HTTPS edge | `COMPAT_CONTROL_TLS=1 COMPAT_EDGE_TLS=1 ./scripts/compat.sh` |
| 12-agent dev cluster with a destroyed Nexus | `./scripts/smoke-cluster.sh --nexus-loss` |
| Containerised dev stack | `make dev` |
| Chart/systemd rendering | `make deploy-lint` |
