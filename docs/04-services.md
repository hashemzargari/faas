# 04 — Service Specifications

Every runtime service: responsibility, contract, state, configuration, scaling, failure behaviour, and SLO. Ports are defaults and configurable.

| Service | Binary | Listeners | Stateful? | Replicas |
|---|---|---|---|---|
| Gateway (S3) | `fass-gateway` | `:8080` HTTP, `:8443` HTTPS, `:9000` admin, `:9090` metrics | no (optional cache) | N behind L4 LB |
| Coordinator (control) | `fass-coordinator` | `:7000` gRPC, `:7001` REST/console API, `:9090` metrics | **yes** (Postgres) | 1 primary + standbys |
| Agent (per disk) | `fass-agent` | `:7100` gRPC, `:7101/udp` QUIC, `:9090` metrics | **yes** (local disk) | one per disk |
| Console | `fass-console` | `:8081` | no | N |
| CLI | `fass` | — | no | — |
| Bridge | `fass-bridge` | `:8082` | jobs in Postgres | N workers |
| Operator | `fass-operator` | webhook `:9443` | K8s CRs | leader-elected |

---

## 1. Gateway — S3 Frontend (`fasss3` analogue)

### 1.1 Responsibility
Terminate S3 over HTTP/1.1 and HTTP/2, authenticate (SigV4 + SigV2), authorise, validate, and route. Owns the **XML/REST contract** and nothing else about storage. Stateless.

### 1.2 In scope
* Routing & addressing (path-style `/{bucket}/{key}` and virtual-hosted `{bucket}.s3.{domain}`).
* SigV4 (`AWS4-HMAC-SHA256`, incl. `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` chunked signing) and SigV2 (`AWS` + `Signature=`).
* Presigned query auth (`X-Amz-Algorithm`/`Signature`/`Credential`/`Expires`). *Cubbit does not document this; we support it (§05 §9).*
* Request parsing: headers, metadata, `x-amz-*`, XML bodies, multipart forms.
* Authorisation call to Coordinator (cached decision, ≤ 1 s TTL).
* Smart Data Placement evaluation → target RC.
* Delegation of payload to the offloader; assembly of XML responses.
* Range requests, conditional requests, ETag/checksum generation.
* `Server`/`x-amz-request-id` headers, per-request structured logging.

### 1.3 Out of scope
Chunking, encryption, erasure coding, shard placement, persistence. The frontend never touches disks.

### 1.4 HTTP surface
```
GET    /                                  ListBuckets
PUT    /{bucket}                          CreateBucket
DELETE /{bucket}                          DeleteBucket
HEAD   /{bucket}                          HeadBucket
GET    /{bucket}?location                 GetBucketLocation
GET    /{bucket}?acl / ?versioning / ?tagging / ?lifecycle / ?object-lock / ?ownershipControls
PUT    /{bucket}?...  (same set)
GET    /{bucket}?list-type=2              ListObjectsV2
GET    /{bucket}?versions                 ListObjectVersions
GET    /{bucket}?uploads                  ListMultipartUploads
GET    /{bucket}?delete                   (POST) DeleteObjects
PUT    /{bucket}/{key}                    PutObject / CopyObject (x-amz-copy-source)
GET    /{bucket}/{key}                    GetObject / HeadObject
DELETE /{bucket}/{key}                    DeleteObject
POST   /{bucket}/{key}?uploads            CreateMultipartUpload
PUT    /{bucket}/{key}?partNumber&uploadId UploadPart / UploadPartCopy
POST   /{bucket}/{key}?uploadId           CompleteMultipartUpload
DELETE /{bucket}/{key}?uploadId           AbortMultipartUpload
GET    /{bucket}/{key}?partNumber&uploadId ListParts
GET|PUT|DELETE /{bucket}/{key}?tagging    Object tagging
GET|PUT    /{bucket}/{key}?retention / ?legal-hold
GET|PUT    /{bucket}/{key}?acl
GET    /healthz /readyz /metrics          (admin listener)
```

### 1.5 Configuration
```yaml
gateway:
  listen: { http: ":8080", https: ":8443", admin: ":9000" }
  tls: { cert_file: /etc/fass/tls/gw.crt, key_file: /etc/fass/tls/gw.key, min_version: "1.3" }
  addressing: { style: path, virtual_host_domain: "s3.fass.internal" }
  auth: { sigv2: true, clock_skew: 15m, presign_max_ttl: 7d }
  s3: { max_object_size: 5TiB, max_single_put: 5GiB, part_size_min: 5MiB, part_size_max: 5GiB, max_parts: 10000, list_page_max: 1000 }
  offloader: { max_concurrent_chunks: 16, chunk_shards_parallel: 16, shard_put_timeout: 5s, shard_put_retries: 2 }
  coordinator: { endpoint: "dns:///coordinator:7000", tls: { ca: /etc/fass/tls/ca.crt, cert: ..., key: ... } }
  cache: { enabled: true, dir: /var/cache/fass, max_bytes: 100GiB, ttl: 10m, shared: false }
  readahead: { chunks: 4, hedge_after: 50ms, max_hedges: 2 }
```

### 1.6 Failure modes
| Failure | Behaviour |
|---|---|
| Coordinator unreachable | serve cached authz + manifests for TTL; writes → `503 SlowDown`; log at error |
| Agent slow/dead | hedged reads; write displacement; chunk fails only if < `local_n` in a group |
| Metadata commit timeout | abort upload, mark shards GC-able, return `500 InternalError` (never a false 200) |
| Client disconnect mid-PUT | cancel pipeline, release chunk buffers, GC orphan shards |
| Overload | token-bucket per tenant + global; `503 SlowDown` with `Retry-After`, never unbounded queueing |

### 1.7 SLO
Availability ≥ 99.95% monthly; p99 PUT (1 MiB, 3-site RC) ≤ 400 ms; p99 GET first byte ≤ 250 ms intra-region; error budget burn alerts at 2%/1 h and 5%/6 h.

---

## 2. Offloader (in-process worker pool)

### 2.1 Responsibility
The data-plane engine: `read → chunk → encrypt → outer RS → inner RS → resolve slots → write shards → commit manifest`. And the exact inverse for reads.

### 2.2 Contract
```go
type Offloader interface {
    Write(ctx context.Context, obj ObjectSpec, body io.Reader) (ManifestRef, error)
    Read(ctx context.Context, ref ManifestRef, rng *ByteRange, w io.Writer) error
    WritePart(ctx context.Context, up UploadID, part int32, body io.Reader) (PartRef, error)
    Assemble(ctx context.Context, up UploadID, parts []PartRef) (ManifestRef, error)
}
```
Bounded by a semaphore (`max_concurrent_chunks`), with per-chunk pipeline stage parallelism and per-agent concurrency caps (default 4 shard streams per agent per chunk).

### 2.3 Invariants
1. **Durability before acknowledgement**: `Write` returns only after every shard `PUT_SHARD` is fsynced-and-acked *and* the manifest is committed.
2. **Bounded memory**: no unbounded buffering; backpressure propagates to the socket read.
3. **Idempotency**: a retried chunk reuses `shard_set_id`; identical shards overwrite by content hash (safe because immutable).
4. **No plaintext at rest**: plaintext buffers are zeroed after encryption (`zeroize` helper).

### 2.4 Failure modes
Shard write fails → displacement; < `local_n` in a group → chunk failure → object failure → orphan GC; manifest commit fails → same. Partial multipart: parts persist independently and are visible via `ListParts`.

---

## 3. Gateway Cache (optional)

Read-through cache of **decrypted chunk plaintext** keyed by `(bucket, key, version, chunk_idx, range)`, or **ciphertext shards** keyed by `shard_id` when operating in zero-knowledge mode (never cache plaintext you are not allowed to see). LRU + TTL; can be shared across a gateway pool via NVMe-oF/NFS for read-heavy workloads (Cubbit: "when deployed on shared storage, the cache improves performance across multiple gateway instances").

Invalidation: version-keyed, so overwrite/delete naturally invalidates; TTL 10 min bounds staleness for cross-gateway shared caches. **Zero-knowledge mode always uses shard-level cache, never plaintext.**

---

## 4. Key Service (gateway-side)

### 4.1 Responsibility
Resolve tenant crypto config and produce/consume file keys. Implements the four modes (§03 §3.2), polls Coordinator every `update_period`, talks KMIP 1.4 for private tenants.

### 4.2 Config
```yaml
crypto:
  mode: remote-multi-keys        # single-key | local-multi-keys | remote-multi-keys | zero-knowledge
  update_period: 1h
  local_keys: { file: /opt/secret/tenant_keys.json }
  kms:
    protocol: kmip1.4
    endpoint: "kms.internal:5696"
    tls: { ca: ..., cert: ..., key: ... }
    timeout: 5s
    cache_ttl: 15m
```
### 4.3 Failure modes
KMS down + key not cached ⇒ `500 InternalError` for the affected tenant only; circuit breaker prevents thread pile-up; never fall back to a weaker key source silently. Wrong key ⇒ `400 InvalidRequest` with `KeyFingerprintMismatch` (detected via manifest fingerprint, not a GCM failure).

---

## 5. Coordinator — Control Plane

One binary, six logical services, one Postgres. Split-ready (each has its own package + gRPC service) but deployed together by default; this matches Cubbit's single centralised Coordinator while keeping the seams.

### 5.0 Shared contract
```protobuf
service Coordinator {
  // identity & policy
  rpc Authenticate (AuthRequest)  returns (Principal);
  rpc Authorize    (AuthzRequest) returns (Decision);
  // buckets & objects
  rpc GetBucket    (BucketRef)    returns (Bucket);
  rpc ResolvePlacement (PlacementRequest) returns (Placement);
  rpc CommitObject (CommitRequest) returns (CommitResult);
  rpc GetManifest  (ManifestRef)  returns (Manifest);
  rpc ListObjects  (ListRequest)  returns (stream ObjectEntry);
  rpc DeleteObject (DeleteRequest) returns (DeleteResult);
  // membership
  rpc Announce     (AnnounceRequest) returns (AnnounceResult);
  rpc Heartbeat    (stream HeartbeatRequest) returns (stream HeartbeatAck);
  // repair
  rpc ReportShardStatus (ShardStatus) returns (Ack);
  rpc ClaimRepairJob    (WorkerRef)   returns (RepairJob);
  rpc CommitRepair      (RepairResult) returns (Ack);
}
```

### 5.1 Identity & Policy Service (`internal/coord/auth`)
* **Models**: `Tenant`, `Project`, `User` (console), `ServiceAccount` (programmatic), `AccessKey{access_key_id, secret_hash(Argon2id), project, scopes, status}`, `Role{Owner,Admin,Member,ReadOnly}`.
* **AuthN**: SigV4/SigV2 verification may happen at the gateway, but the **decision** comes from the Coordinator: `Authenticate` returns a `Principal` with cached key material (HMAC key) and TTL so the gateway can verify signatures locally without a round trip. ⇒ gateway verifies, coordinator authorises.
* **AuthZ chain** (mirrors Cubbit's documented four stages): access key → **IAM policy** (explicit deny wins) → **bucket policy** (deny wins, else fall through; managed out-of-band, no S3 API) → **ACL** (must explicitly allow for cross-account). Actions are `crn`-scoped, e.g. `crn:eu-west-1:s3:object:tenant_<uuid>/project_<uuid>/bucket/key`.
* **CRN grammar**: `crn:<region>:s3:{bucket|object|project|tenant|swarm}:<resource-path>`, actions `s3:*` plus `iam:*`, `ds3:*`.
* **Policy language**: JSON, `syntax_version 2023-10-16`, statements of `{effect, actions[], resources[], conditions{}}`; condition keys `s3:prefix`, `s3:max-keys`, `s3:versionid`, `s3:x-amz-acl`, `s3:ExistingObjectTag/*`.
* **Cubbit fidelity notes**: default bucket ownership control is `ObjectWriter`; `BucketOwnerEnforced` rejects ACL writes with `AccessControlListNotSupported`; changing ownership to `BucketOwnerEnforced` while a bucket ACL grants others ⇒ `InvalidBucketAclWithObjectOwnership`; `x-amz-expected-bucket-owner` **is** enforced; `x-amz-source-expected-bucket-owner` is not.
* **Service accounts**: project-scoped IAM users; secrets shown once, stored as Argon2id; an invited-but-unused account is soft-deleted after 7 days (Cubbit-documented behaviour).

### 5.2 Metadata Service (`internal/coord/meta`)
System of record in **PostgreSQL**. Repository interfaces keep an embedded dev mode possible (see D-C in docs/06 — a dependency-free journal store, not SQLite). Core tables (§02 §5, full DDL in `docs/schema.sql` when coding starts):

`tenants, projects, users, memberships, access_keys, iam_policies, bucket_policies, swarms, nexuses, nodes, agents, disks, rings, redundancy_classes, buckets, objects, object_versions, manifests, shard_sets, shard_displacements, uploads, upload_parts, bucket_acls, object_acls, object_tags, retention, legal_holds, lifecycle_rules, deletion_queue, repair_jobs, usage_hourly, audit_log`

Design rules:
* **Manifest offload**: chunk tables are content-addressed blobs (≤ 1 MiB pages, zstd) in `manifest_blobs`, referenced by hash; the `manifests` row is small and hot.
* **List performance**: `objects(bucket_id, key, version_id, is_latest)` unique index; `ListObjectsV2` is an index range scan with delimiter grouping done in SQL (`substr` on the first delimiter) — no object store round trips.
* **Atomic version flip**: `UPDATE object_versions SET is_latest=false WHERE ...; INSERT new version; UPDATE objects SET latest_version=...` in one serializable transaction.
* **Deletion**: never `DELETE` payload rows synchronously; enqueue.
* **Retention**: `retention(mode, retain_until, legal_hold)` columns on the version row; enforced in the same transaction as delete.

### 5.3 Placement Service (`internal/coord/placement`)
* Stateless compute over a topology snapshot refreshed every 5 s (and invalidated on membership change).
* API: `ResolvePlacement{shard_set_id, rc_id, ring_id, size, tenant} → {slots[]}`; `PlanRepair`; `PlanRebalance`.
* Deterministic (§03 §4.3), auditable: every decision can be replayed from `(shard_set_id, topology_snapshot_id)`.
* Returns endpoints, not just ids: gateway connects directly to agents.

### 5.4 Membership & Health Service (`internal/coord/membership`)
* **Agent announce** (the only membership protocol Cubbit documents):
```http
POST /v1/agents/announce
{ "public_key": "<ed25519-b64>", "secret": "<one-time-secret>",
  "node_id": "<uuid>", "disk_id": "<uuid>", "port": 7101,
  "capacity_bytes": 18000000000000, "version": "1.4.2" }
→ 200 { "agent_id": "<uuid>", "certificate": "<PEM>", "ring_ids": ["..."] }
```
Error taxonomy kept intentionally identical to Cubbit's published one: `400 Port mismatch`, `403 Secret not found`, `409 Agent with the same public key already exists`, `409 agent is not in pending status`, `409 Secret mismatch`, `503 under maintenance`. New agents start in `pending` and must be activated (console/API), matching Cubbit's flow.
* **Heartbeat**: bidirectional stream, 5 s interval; carries `{load, free_bytes, shard_count, bw_used, scrub_cursor, digest}`. Miss 3 ⇒ `SUSPECT`; 60 s ⇒ `OFFLINE`; explicit `DECOMMISSION` ⇒ drains.
* **Scores**: `uptime_score` EWMA (30 d), `reputation` (churn, nightly offline), `load`, `bw_headroom`, `rtt_class` (measured via gateway probes).

### 5.5 Recovery Orchestrator (`internal/coord/recovery`)
* Leader-elected (Postgres advisory lock). Computes redundancy state, enqueues repair jobs, enforces budgets (§03 §5).
* `ClaimRepairJob` / `CommitRepair` with CAS on `shard_set.generation`. Lease-based, idempotent.
* Emits `RepairStarted/Completed/Failed` events and exposes queue depth, MTTR, bytes-repaired metrics.

### 5.6 Usage & Accounting (`internal/coord/usage`)
* Per-hour rollups per project/bucket: `storage_byte_hours`, `objects_total`, `objects_non_empty` (Cubbit bills empty and non-empty separately), `ingress_bytes`, `egress_bytes`.
* **Minimum chargeable size 256 KB** per object (Cubbit's published rule); bandwidth metered on GET responses and reset monthly.
* Feeds console charts and the `GET /v1/usage` API. No invoicing.

### 5.7 Coordinator config (abridged)
```yaml
coordinator:
  listen: { grpc: ":7000", http: ":7001" }
  db:
    dsn: "postgres://fass@pg-primary/fass?sslmode=verify-full"
    max_conns: 40
    statement_timeout: 5s
  ha: { mode: primary, failover: patroni }
  membership: { heartbeat_interval: 5s, suspect_after: 15s, offline_after: 60s, repair_grace: 10m }
  placement: { headroom: 1.15, ring_full_pct: 85, weights: { uptime: .25, load: .25, bw: .15, reputation: .15, capacity: .10, rtt: .10 } }
  recovery: { local_repair_parallelism: 8, geo_repair_parallelism: 2, per_site_budget_mbps: 200, scrub_period: 168h }
  crypto: { kmip_endpoint: "", tenant_seed_rotation: 90d }
```

### 5.8 Coordinator SLO
Metadata write availability 99.9% (single-region, sync standby); `ResolvePlacement` p99 ≤ 15 ms; `CommitObject` p99 ≤ 40 ms; failover RTO ≤ 60 s, RPO 0 intra-region.

---

## 6. Agent — per-disk shard daemon

### 6.1 Responsibility
Own exactly one disk. Store/serve immutable shards. Report health and inventory. Participate in local repair and scrubbing.

### 6.2 gRPC surface
```protobuf
service Agent {
  rpc PutShard    (stream PutShardRequest) returns (PutShardResult);
  rpc GetShard    (GetShardRequest)        returns (stream ShardChunk);
  rpc DeleteShards(DeleteShardsRequest)    returns (DeleteShardsResult);
  rpc HasShards   (HasShardsRequest)       returns (HasShardsResult);
  rpc Inventory   (InventoryRequest)       returns (stream InventoryEntry);
  rpc ScrubRange  (ScrubRequest)           returns (stream ScrubResult);
  rpc Stats       (StatsRequest)           returns (AgentStats);
}
```
Shard transfer listens on QUIC (`:7101/udp`, mTLS, ALPN `fass-shard/1`); one bidirectional stream per shard, 256 KiB frames, per-stream flow control.

### 6.3 Local storage
```
/data/
  shards/<aa>/<bb>/<shard_id>.shard
  index/pebble/                  # shard_id → meta; ~120 B/entry
  incoming/*.partial
  quarantine/                    # failed-checksum shards, kept for forensics
  state.json                     # agent identity, disk uuid, format version
```
* Write: `open temp → write header+payload → fsync(file) → rename → fsync(dir)`. No WAL for payload.
* Read: `open → verify header → stream` (checksum verified end-to-end at the gateway too).
* Capacity: reserve 5% (configurable) from the filesystem so the disk never fills; report `free_bytes` net of reservation.

### 6.4 Config
```yaml
agent:
  disk: { path: /data, reserve_pct: 5, max_write_iops: 0 }
  listen: { grpc: ":7100", quic: ":7101" }
  coordinator: { endpoint: "coordinator:7000", announce_url: "https://coordinator:7001/v1/agents/announce" }
  identity: { key_file: /var/lib/fass/agent.key, cert_file: /var/lib/fass/agent.crt }
  scrub: { enabled: true, period: 168h, max_bytes_per_sec: 50MiB }
  repair: { enabled: true, max_concurrent_jobs: 2 }
  limits: { max_shard_bytes: 8MiB, read_mbps: 0, write_mbps: 0 }
```
### 6.5 Failure modes
| Failure | Behaviour |
|---|---|
| Coordinator unreachable | keep serving reads/writes already placed; buffer telemetry; refuse new replica targets (gateway won't send any) |
| Disk full | reject `PutShard` with `RESOURCE_EXHAUSTED`; Coordinator de-weights the agent |
| Corrupt shard | quarantine + report `CORRUPT` → repair |
| Disk pulled / agent restart | `state.json` identity check; mismatch ⇒ refuse to start (prevents serving another disk's shards — Cubbit's `409 same public key` concern) |
| Partial write after crash | `.partial` sweep on boot |

### 6.6 SLO
Shard GET p99 ≤ 20 ms (NVMe) / ≤ 60 ms (HDD, sequential); PUT p99 ≤ 150 ms; heartbeat success ≥ 99.99%; scrub overhead ≤ 5% of disk bandwidth.

---

## 7. Repair Worker (`internal/agent/repair`)

### 7.1 Responsibility
Execute a `RepairJob`: fetch sources, RS-decode, re-encode, write targets, report. Runs co-located in agents (local repair) and in gateways (geo repair). **Holds no keys.**

### 7.2 Job schema
```json
{ "job_id": "uuid", "type": "local|geo|corruption|rebalance",
  "shard_set_id": "uuid", "chunk_index": 42, "generation": 7,
  "params": {"geo_n":2,"geo_k":1,"local_n":16,"local_k":4},
  "sources": [{"geo_group":0,"local_index":3,"agent_id":"...","endpoint":"10.0.0.7:7101"}],
  "targets": [{"geo_group":0,"local_index":3,"agent_id":"...","endpoint":"10.0.0.9:7101"}],
  "max_mbps": 200, "deadline": "2026-10-24T18:00:00Z" }
```
Idempotent: re-running produces identical shard bytes (RS is deterministic given inputs) and `PUT_SHARD` is content-addressed.

### 7.3 Safety
* Verifies every fetched shard's checksum before decode; a bad source is reported and the job retried with a substitute.
* Never deletes sources; deletion is the Coordinator's job after the CAS commit.
* Self-throttles against the site budget and yields to foreground traffic (token bucket shared with the transport).

---

## 8. Console (`fass-console`)

Server-rendered Go templates + HTMX, embedded assets. Mirrors Cubbit's Composer console information architecture:

`Operators · Tenants · Projects · Users · Access Keys · Swarms · Nexuses · Nodes · Agents · Rings · Redundancy Classes · Buckets · Usage/Reports · Alerts · Audit Log · Bridge`

Flows: create Swarm → create Nexus → "Deploy nodes" wizard (generates Ansible bundle tar, exactly like Cubbit) → create RC (with live ratio preview and feasibility validation) → connect Tenant → gateway config incl. Smart Data Placement JSON editor with validation.

AuthN via local users or OIDC/SAML (Cubbit supports SAML 2.0, OIDC/OP, Google, Microsoft). RBAC: Owner / Admin / Member / Read-only.

---

## 9. CLI (`fass`)

```
fass cluster init|status|upgrade
fass swarm   create|ls|describe        fass nexus create|ls
fass node    deploy --hosts h1,h2 --disk-prefix /dev/sd --disks 12 --out ansible.tar.gz
fass rc      create --geo 2+1 --local 16+4 --aag 2 [--dry-run ratio]
fass ring    ls|capacity
fass tenant  create|ls|quota           fass project create|ls
fass gateway register|edit --default-rc <id> --sdp-policy policy.json
fass bucket  ls|create|rm              fass ls|cp|rm|presign (S3 client ergonomics)
fass repair  status|trigger|pause      fass rebalance plan|run
fass doctor  (topology validation, orphan scan, ratio audit)
```

---

## 10. Bridge (`fass-bridge`)

Separate control plane (Cubbit uses a distinct endpoint and `x-cbt-*` headers rather than SigV4; we use a dedicated service too, with our own auth).
```http
POST   /v1/bridges                 → 201 {id}     (creates destination buckets, no copy yet)
POST   /v1/bridges/{id}/start      → 204           (idempotent; begins background migration)
GET    /v1/bridges/{id}            → {status, buckets:[{migrated,failed,locked}]}
DELETE /v1/bridges/{id}            → 204           (stops tracking; no data action)
```
Semantics: reads proxy to the source until an object is copied; writes always go to FASS; each object is deleted from the source only after a verified copy; failures do not auto-retry and are counted in `failed`; buckets end `completed` even with failures. Preconditions: no Object Lock on source; permanent credentials (no STS).

**Status: implemented** in `cmd/fass-bridge` + `internal/bridge`:
* the **mover** (control API above) copies, verifies by size + SHA-256 read-back, then deletes the source copy; it is resumable via a per-bridge JSON journal and bounded by `--concurrency` plus optional byte/request rate limits;
* the **S3-compatible proxy** (`--s3-listen`) is the adoption path: clients point at it before migration finishes. GET/HEAD serve the target when it is at least as new as the source and fall through to the source otherwise (Range supported, target retried if the copy won the race); PUT/DELETE/multipart always target; listings come from the source while a bucket is in-progress and are marked `listing_source:"source"` in the status API (merged pagination deferred deliberately) and switch to the target on completion; reads that fall through are prioritised for copying. SigV4 is verified against the target credentials and the listener uses the same TLS/mTLS posture as the rest of the cluster. See docs/08 §5.

---

## 11. Operator (`fass-operator`) & Installer

**K8s**: CRDs `Gateway`, `GatewayPool`, `AgentDaemonSet`; the operator renders ConfigMap/Secret/Deployment/Service/Ingress per gateway, supports TLS rotation, `--uninstall`, and per-tenant crypto injection (matching `gateway-operator` + `gods3-config`).
**Bare metal**: `fass node deploy` emits an Ansible bundle (`inventory`, `playbook.yml`, `README`) that installs the agent container, creates the data dir, sets ports per disk, and runs `agent announce` with a one-time secret.

---

## 12. Cross-cutting contract: error taxonomy

Every service returns a typed error mapped to an S3 XML error at the gateway edge:

| Internal code | S3 `Code` | HTTP |
|---|---|---|
| `ErrAccessDenied` | `AccessDenied` | 403 |
| `ErrNoSuchBucket` | `NoSuchBucket` | 404 |
| `ErrNoSuchKey` | `NoSuchKey` | 404 |
| `ErrPreconditionFailed` | `PreconditionFailed` | 412 |
| `ErrInvalidPart` | `InvalidPart` | 400 |
| `ErrEntityTooLarge` | `EntityTooLarge` | 400 |
| `ErrObjectLocked` | `AccessDenied` | 403 |
| `ErrNotImplemented` | `NotImplemented` | 501 |
| `ErrSlowDown` | `SlowDown` | 503 |
| `ErrInternal` | `InternalError` | 500 |
| `ErrKeyFingerprintMismatch` | `InvalidRequest` | 400 |

Response envelope (undocumented by Cubbit; we adopt the AWS shape):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message>
<Resource>/bucket/key</Resource><RequestId>...</RequestId></Error>
```
Every response carries `x-amz-request-id` and `x-amz-id-2`; `Server: fass/<version>`.
