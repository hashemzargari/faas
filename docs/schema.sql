-- FASS coordinator metadata: logical entity model + PostgreSQL adapter layout
--
-- FRAMING (ADR-3b, docs/02-architecture.md): this file documents the *entity
-- shape* the coordinator persists and the *physical layout* the PostgreSQL
-- adapter uses. It is not yet queried directly as a relational domain model: the
-- v1 adapter stores every record family in the two tables documented in the
-- appendix (`kv` + `blobs`), behind the storage.Store interface. The entity
-- tables below are the drift-gated documentation of what those JSON records
-- encode, and they are the target of the planned promotion path (typed identity
-- columns beside the JSON payload, queried directly) — do not delete them.
--
-- Tables actually created/used by the PostgreSQL adapter today:
--   schema_migrations   applied migration versions (managed by `fass-coordinator migrate`)
--   kv                  (space, key) -> jsonb record; B-tree PK, bounded range scans only
--   blobs               content-addressed compressed manifest pages (immutable)
-- Everything else in this file is the logical model: it names the record fields,
-- constraints, and relationships that the `kv` JSON documents satisfy.
--
-- Drift guard: internal/coord/schema_drift_test.go parses this file and the
-- coordinator's record structs and fails the build if a persisted field has no
-- documented column/child table here. Intentional divergences (renamed columns,
-- fields normalised into child tables, nested records the relational model
-- flattens) are declared explicitly in that test, so every difference is
-- reviewable rather than accidental. Add a field to a record without documenting
-- it here and the suite goes red.
--
-- Design rules (docs/04-services.md §5.2):
--   * manifests are content-addressed, compressed blobs; the hot version row is small;
--   * object listing is an ordered index range scan on (bucket_id, key);
--   * version flips and delete markers are one serializable transaction;
--   * payload rows are never synchronously deleted: deletion_queue defers shard GC;
--   * retention/legal hold are enforced in the same transaction as delete;
--   * IDs are UUIDv4 strings (docs/07 §3); times are UTC timestamptz.

BEGIN;

-- ---------------------------------------------------------------------------
-- Schema versioning
-- ---------------------------------------------------------------------------

CREATE TABLE schema_migrations (
    version      integer      PRIMARY KEY,
    applied_at   timestamptz  NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Identity, tenancy, policy
-- ---------------------------------------------------------------------------

CREATE TABLE tenants (
    tenant_id         uuid         PRIMARY KEY,
    name              text         NOT NULL,
    -- Data residency: the only Nexuses this tenant's data may live in.
    -- Empty array means "no fence" (docs/03 §4.1, docs/04 §5.1).
    geo_fence         uuid[]       NOT NULL DEFAULT '{}',
    default_rc_id     uuid,
    -- Opaque key seed, wrapped by the coordinator KEK/KMIP. The coordinator
    -- never derives object keys from it (docs/03 §3.5).
    key_seed_wrapped  bytea,
    created_at        timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE projects (
    project_id   uuid         PRIMARY KEY,
    tenant_id    uuid         NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    name         text         NOT NULL,
    created_at   timestamptz  NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);
CREATE INDEX projects_tenant_idx ON projects (tenant_id);

CREATE TABLE users (               -- console/IdP users; not S3 credentials
    user_id       uuid         PRIMARY KEY,
    tenant_id     uuid         REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    email         text         NOT NULL,
    display_name  text         NOT NULL DEFAULT '',
    role          text         NOT NULL CHECK (role IN ('Owner','Admin','Member','ReadOnly')),
    status        text         NOT NULL DEFAULT 'active' CHECK (status IN ('active','invited','disabled')),
    created_at    timestamptz  NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, email)
);

CREATE TABLE memberships (
    project_id  uuid         NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    user_id     uuid         NOT NULL REFERENCES users (user_id) ON DELETE CASCADE,
    role        text         NOT NULL CHECK (role IN ('Owner','Admin','Member','ReadOnly')),
    PRIMARY KEY (project_id, user_id)
);

CREATE TABLE access_keys (
    access_key_id  text         PRIMARY KEY,
    -- The coordinator must return the HMAC secret to gateways (VerifySignature),
    -- so the column holds a wrapped secret, not an Argon2 hash. Group/tenant
    -- metadata below is the authorisation input.
    secret_wrapped bytea        NOT NULL,
    tenant_id      uuid         NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    project_id     uuid         NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    is_root        boolean      NOT NULL DEFAULT false,
    groups         text[]       NOT NULL DEFAULT '{}',
    status         text         NOT NULL DEFAULT 'Active' CHECK (status IN ('Active','Inactive')),
    expires_at     timestamptz,
    created_at     timestamptz  NOT NULL DEFAULT now(),
    last_used_at   timestamptz
);
CREATE INDEX access_keys_project_idx ON access_keys (tenant_id, project_id);

-- IAM policies are scoped to exactly one of tenant / project / access key.
CREATE TABLE iam_policies (
    policy_id       uuid         PRIMARY KEY,
    name            text         NOT NULL,
    scope           text         NOT NULL CHECK (scope IN ('tenant','project','access_key')),
    tenant_id       uuid         REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    project_id      uuid         REFERENCES projects (project_id) ON DELETE CASCADE,
    access_key_id   text         REFERENCES access_keys (access_key_id) ON DELETE CASCADE,
    statements      jsonb        NOT NULL,   -- [{effect,actions[],resources[],conditions{}}]
    created_at      timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT iam_policy_scope_target CHECK (
        (scope = 'tenant'     AND tenant_id IS NOT NULL) OR
        (scope = 'project'    AND tenant_id IS NOT NULL AND project_id IS NOT NULL) OR
        (scope = 'access_key' AND access_key_id IS NOT NULL)
    )
);
CREATE INDEX iam_policies_tenant_idx ON iam_policies (tenant_id);
CREATE INDEX iam_policies_project_idx ON iam_policies (project_id);
CREATE INDEX iam_policies_key_idx ON iam_policies (access_key_id);

-- ---------------------------------------------------------------------------
-- Topology: Swarm -> Nexus -> Node -> Agent
-- ---------------------------------------------------------------------------

CREATE TABLE swarms (
    swarm_id    uuid         PRIMARY KEY,
    name        text         NOT NULL,
    region      text         NOT NULL DEFAULT 'eu-west-1',
    created_at  timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE nexuses (
    nexus_id        uuid         PRIMARY KEY,
    swarm_id        uuid         NOT NULL REFERENCES swarms (swarm_id) ON DELETE CASCADE,
    name            text         NOT NULL,
    region          text         NOT NULL DEFAULT 'eu-west-1',
    -- Operator-declared: no data leaves a DEGRADED Nexus for writes.
    write_degraded  boolean      NOT NULL DEFAULT false,
    created_at      timestamptz  NOT NULL DEFAULT now(),
    UNIQUE (swarm_id, name)
);

CREATE TABLE nodes (
    node_id     uuid primary key,
    nexus_id    uuid         NOT NULL REFERENCES nexuses (nexus_id) ON DELETE CASCADE,
    hostname    text         NOT NULL,
    -- Used by the placement diversity pass (same rack => 0.2 proximity).
    rack        text         NOT NULL DEFAULT '',
    created_at  timestamptz  NOT NULL DEFAULT now()
);
CREATE INDEX nodes_nexus_idx ON nodes (nexus_id);

CREATE TABLE disks (
    disk_id     uuid         PRIMARY KEY,
    node_id     uuid         NOT NULL REFERENCES nodes (node_id) ON DELETE CASCADE,
    dev_path    text         NOT NULL,
    capacity_bytes bigint    NOT NULL CHECK (capacity_bytes >= 0),
    created_at  timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE agents (
    agent_id            uuid         PRIMARY KEY,
    node_id             uuid         NOT NULL REFERENCES nodes (node_id) ON DELETE CASCADE,
    nexus_id            uuid         NOT NULL REFERENCES nexuses (nexus_id),
    -- Agent-reported disk identity (the engine's identity unit is one agent per
    -- disk; the disks table is inventory metadata, not a foreign key here).
    disk_id             text         NOT NULL,
    hostname            text         NOT NULL DEFAULT '',
    endpoint            text         NOT NULL DEFAULT '',
    port                integer      CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    expected_port       integer      CHECK (expected_port IS NULL OR expected_port BETWEEN 1 AND 65535),
    version             text         NOT NULL DEFAULT '',
    public_key          bytea,                     -- ed25519; unique across the swarm
    -- One-time announce secret: digest only, consumed on success (docs/07 §1.7).
    secret_hash         bytea,
    secret_expires_at   timestamptz,
    capacity_bytes      bigint       NOT NULL DEFAULT 0 CHECK (capacity_bytes >= 0),
    free_bytes          bigint       NOT NULL DEFAULT 0 CHECK (free_bytes >= 0),
    used_bytes          bigint       NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    shard_count         bigint       NOT NULL DEFAULT 0 CHECK (shard_count >= 0),
    state               text         NOT NULL DEFAULT 'pending'
                          CHECK (state IN ('pending','active','suspect','offline','decommissioning')),
    state_changed_at    timestamptz  NOT NULL DEFAULT now(),
    last_seen_at        timestamptz,
    registered_at       timestamptz  NOT NULL DEFAULT now(),
    activated_at        timestamptz,
    uptime_score        double precision NOT NULL DEFAULT 1.0 CHECK (uptime_score BETWEEN 0 AND 1),
    reputation          double precision NOT NULL DEFAULT 1.0 CHECK (reputation BETWEEN 0 AND 1),
    load_ewma           double precision NOT NULL DEFAULT 0   CHECK (load_ewma BETWEEN 0 AND 1),
    bw_headroom         double precision NOT NULL DEFAULT 1.0 CHECK (bw_headroom BETWEEN 0 AND 1),
    rtt_score           double precision NOT NULL DEFAULT 0.5 CHECK (rtt_score BETWEEN 0 AND 1),
    scrub_cursor        text         NOT NULL DEFAULT '',
    inventory_digest    text         NOT NULL DEFAULT '',
    bandwidth_bps       bigint       NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX agents_public_key_uniq ON agents (public_key) WHERE public_key IS NOT NULL;
CREATE UNIQUE INDEX agents_node_disk_uniq ON agents (node_id, disk_uuid);
CREATE INDEX agents_state_idx ON agents (state);
CREATE INDEX agents_nexus_idx ON agents (nexus_id);

CREATE TABLE rings (
    ring_id       uuid         PRIMARY KEY,
    name          text         NOT NULL DEFAULT '',
    rc_id         uuid         NOT NULL,          -- FK added after redundancy_classes
    nexus_ids     uuid[]       NOT NULL,
    capacity_bytes bigint      NOT NULL DEFAULT 0 CHECK (capacity_bytes >= 0),
    used_bytes    bigint       NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    epoch         bigint       NOT NULL DEFAULT 1,
    created_at    timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT ring_capacity_sane CHECK (used_bytes <= capacity_bytes * 2)
);
CREATE INDEX rings_rc_idx ON rings (rc_id);

-- Agents may belong to several rings (multi-tenancy/tiering, docs/03 §4.6).
CREATE TABLE ring_agents (
    ring_id   uuid NOT NULL REFERENCES rings (ring_id) ON DELETE CASCADE,
    agent_id  uuid NOT NULL REFERENCES agents (agent_id) ON DELETE CASCADE,
    PRIMARY KEY (ring_id, agent_id)
);

CREATE TABLE redundancy_classes (
    rc_id       uuid         PRIMARY KEY,
    name        text         NOT NULL,
    geo_n       integer      NOT NULL CHECK (geo_n BETWEEN 1 AND 16),
    geo_k       integer      NOT NULL CHECK (geo_k BETWEEN 0 AND 8),
    local_n     integer      NOT NULL CHECK (local_n BETWEEN 2 AND 64),
    local_k     integer      NOT NULL CHECK (local_k BETWEEN 0 AND 32),
    aag         integer      NOT NULL CHECK (aag >= 1),
    chunk_size  bigint       NOT NULL CHECK (chunk_size BETWEEN 4194304 AND 67108864),
    created_at  timestamptz  NOT NULL DEFAULT now(),
    -- docs/03 §2.2 parameter constraints.
    CONSTRAINT rc_geo_width  CHECK (geo_n + geo_k <= 16),
    CONSTRAINT rc_local_width CHECK (local_n + local_k <= 64),
    CONSTRAINT rc_aag_bounds CHECK (aag <= local_n + local_k),
    CONSTRAINT rc_chunk_divisible CHECK (chunk_size % (geo_n * local_n) = 0),
    CONSTRAINT rc_shard_min CHECK (chunk_size / (geo_n * local_n) >= 4096),
    CONSTRAINT rc_ratio CHECK (((geo_n + geo_k)::numeric / geo_n) * ((local_n + local_k)::numeric / local_n) <= 4.0)
);

ALTER TABLE rings
    ADD CONSTRAINT rings_rc_fk FOREIGN KEY (rc_id) REFERENCES redundancy_classes (rc_id);

ALTER TABLE tenants
    ADD CONSTRAINT tenants_default_rc_fk FOREIGN KEY (default_rc_id) REFERENCES redundancy_classes (rc_id);

-- ---------------------------------------------------------------------------
-- Buckets, object versions, manifests
-- ---------------------------------------------------------------------------

CREATE TABLE buckets (
    bucket_id      uuid         PRIMARY KEY,
    name           text         NOT NULL,
    tenant_id      uuid         NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    project_id     uuid         NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    region         text         NOT NULL DEFAULT 'eu-west-1',
    versioning     text         NOT NULL DEFAULT '' CHECK (versioning IN ('','Enabled','Suspended')),
    object_lock    boolean      NOT NULL DEFAULT false,
    ownership      text         NOT NULL DEFAULT 'ObjectWriter'
                     CHECK (ownership IN ('ObjectWriter','BucketOwnerEnforced')),
    default_rc_id  uuid         REFERENCES redundancy_classes (rc_id),
    quota_bytes    bigint       NOT NULL DEFAULT 0 CHECK (quota_bytes >= 0),
    -- Opaque lifecycle document (the gateway validates its XML shape).
    lifecycle_xml  bytea,
    created_at     timestamptz  NOT NULL DEFAULT now(),
    UNIQUE (name)                                  -- S3 bucket names are global
);
CREATE INDEX buckets_tenant_idx ON buckets (tenant_id, project_id);

-- Managed out-of-band (no S3 API), part of the authorisation chain.
CREATE TABLE bucket_policies (
    bucket_id   uuid         PRIMARY KEY REFERENCES buckets (bucket_id) ON DELETE CASCADE,
    policy      jsonb        NOT NULL,
    updated_at  timestamptz  NOT NULL DEFAULT now()
);

-- Small hot row: pointer from (bucket, key) to the visible version.
CREATE TABLE objects (
    bucket_id       uuid         NOT NULL REFERENCES buckets (bucket_id) ON DELETE CASCADE,
    key             text         NOT NULL,
    latest_version_id uuid,
    seq             bigint       NOT NULL,
    is_delete_marker boolean     NOT NULL DEFAULT false,
    size            bigint       NOT NULL DEFAULT 0,
    etag            text         NOT NULL DEFAULT '',
    last_modified   timestamptz  NOT NULL DEFAULT now(),
    storage_class   text         NOT NULL DEFAULT 'STANDARD',
    PRIMARY KEY (bucket_id, key)
);
CREATE INDEX objects_listing_idx ON objects (bucket_id, key) WHERE NOT is_delete_marker;

-- One row per object version. Tombstoned rows stay until the deletion queue has
-- collected the shards (metadata is the sole source of truth).
CREATE TABLE object_versions (
    bucket_id        uuid         NOT NULL REFERENCES buckets (bucket_id) ON DELETE CASCADE,
    key              text         NOT NULL,
    version_id       uuid         NOT NULL,
    seq              bigint       NOT NULL,
    is_delete_marker boolean      NOT NULL DEFAULT false,
    deleted          boolean      NOT NULL DEFAULT false,
    deleted_at       timestamptz,
    size             bigint       NOT NULL DEFAULT 0 CHECK (size >= 0),
    etag             text         NOT NULL DEFAULT '',
    manifest_hash    bytea,                        -- NULL for zero-byte objects
    chunk_size       bigint       NOT NULL DEFAULT 16777216,
    content_type     text         NOT NULL DEFAULT '',
    user_meta        jsonb        NOT NULL DEFAULT '{}',
    acl              jsonb,
    rc_id            uuid         REFERENCES redundancy_classes (rc_id),
    ring_id          uuid         REFERENCES rings (ring_id),
    storage_class    text         NOT NULL DEFAULT 'STANDARD',
    retention_mode   text         CHECK (retention_mode IN ('GOVERNANCE','COMPLIANCE')),
    retain_until     timestamptz,
    legal_hold       boolean      NOT NULL DEFAULT false,
    created_at       timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_id, key, version_id)
);
-- Version listings: key ascending, newest first.
CREATE INDEX object_versions_listing_idx ON object_versions (bucket_id, key, seq DESC);
-- Point lookup by version id (data path).
CREATE UNIQUE INDEX object_versions_id_uniq ON object_versions (bucket_id, version_id);
CREATE INDEX object_versions_manifest_idx ON object_versions (manifest_hash);
CREATE INDEX object_versions_deleted_idx ON object_versions (deleted) WHERE deleted;

-- Content-addressed chunk tables (content-addressed, flate-compressed JSON).
CREATE TABLE manifest_blobs (
    manifest_hash  bytea        PRIMARY KEY,       -- SHA-256 of canonical JSON
    blob           bytea        NOT NULL           CHECK (octet_length(blob) <= 1048576),
    created_at     timestamptz  NOT NULL DEFAULT now()
);

-- Explicit placement for v1 (docs/03 §4.5 scale-out path: base placement is a
-- pure function of (ring, epoch, shard_set_id); v1 stores it for auditable replay).
CREATE TABLE shard_sets (
    shard_set_id  uuid         PRIMARY KEY,
    rc_id         uuid         NOT NULL REFERENCES redundancy_classes (rc_id),
    ring_id       uuid         NOT NULL REFERENCES rings (ring_id),
    chunk_index   bigint       NOT NULL DEFAULT 0,
    generation    bigint       NOT NULL DEFAULT 1,
    placement_hash bytea,
    displacement_blob bytea,                       -- varint delta-encoded, usually empty
    created_at    timestamptz  NOT NULL DEFAULT now()
);

CREATE TABLE shard_placements (
    shard_set_id uuid         NOT NULL REFERENCES shard_sets (shard_set_id) ON DELETE CASCADE,
    shard_index  integer      NOT NULL CHECK (shard_index >= 0),
    geo_group    integer      NOT NULL CHECK (geo_group >= 0),
    local_index  integer      NOT NULL CHECK (local_index >= 0),
    agent_id     uuid         NOT NULL REFERENCES agents (agent_id),
    checksum     bigint       NOT NULL,            -- BigEndian(SHA-256(shard)[:8])
    PRIMARY KEY (shard_set_id, shard_index)
);

CREATE TABLE shard_displacements (
    shard_set_id   uuid        NOT NULL REFERENCES shard_sets (shard_set_id) ON DELETE CASCADE,
    slot           integer     NOT NULL,
    original_agent uuid        NOT NULL REFERENCES agents (agent_id),
    actual_agent   uuid        NOT NULL REFERENCES agents (agent_id),
    generation     bigint      NOT NULL,
    reason         text        NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (shard_set_id, slot, generation)
);

-- ACLs: bucket and object (object ACL is per version, like S3).
CREATE TABLE bucket_acls (
    bucket_id  uuid         PRIMARY KEY REFERENCES buckets (bucket_id) ON DELETE CASCADE,
    owner_id   text         NOT NULL,
    grants     jsonb        NOT NULL DEFAULT '[]'
);

CREATE TABLE object_acls (
    bucket_id  uuid         NOT NULL,
    key        text         NOT NULL,
    version_id uuid         NOT NULL,
    owner_id   text         NOT NULL,
    grants     jsonb        NOT NULL DEFAULT '[]',
    PRIMARY KEY (bucket_id, key, version_id),
    FOREIGN KEY (bucket_id, key, version_id)
        REFERENCES object_versions (bucket_id, key, version_id) ON DELETE CASCADE
);

CREATE TABLE object_tags (
    bucket_id  uuid         NOT NULL,
    key        text         NOT NULL,
    version_id uuid         NOT NULL,
    tag_key    text         NOT NULL CHECK (length(tag_key) BETWEEN 1 AND 128),
    tag_value  text         NOT NULL CHECK (length(tag_value) <= 256),
    PRIMARY KEY (bucket_id, key, version_id, tag_key),
    FOREIGN KEY (bucket_id, key, version_id)
        REFERENCES object_versions (bucket_id, key, version_id) ON DELETE CASCADE
);

-- Object-lock history (the current state is denormalised onto object_versions).
CREATE TABLE legal_holds (
    bucket_id   uuid         NOT NULL,
    key         text         NOT NULL,
    version_id  uuid         NOT NULL,
    legal_hold  boolean      NOT NULL,
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_id, key, version_id),
    FOREIGN KEY (bucket_id, key, version_id)
        REFERENCES object_versions (bucket_id, key, version_id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Multipart
-- ---------------------------------------------------------------------------

CREATE TABLE uploads (
    upload_id      uuid         PRIMARY KEY,
    bucket_id      uuid         NOT NULL REFERENCES buckets (bucket_id) ON DELETE CASCADE,
    key            text         NOT NULL,
    version_id     uuid,                           -- gateway-assigned, may be NULL until complete
    chunk_size     bigint       NOT NULL DEFAULT 16777216,
    content_type   text         NOT NULL DEFAULT '',
    user_meta      jsonb        NOT NULL DEFAULT '{}',
    tags           jsonb        NOT NULL DEFAULT '{}',
    rc_id          uuid         REFERENCES redundancy_classes (rc_id),
    ring_id        uuid         REFERENCES rings (ring_id),
    storage_class  text         NOT NULL DEFAULT 'STANDARD',
    encryption     jsonb        NOT NULL DEFAULT '{}',
    retention      jsonb,                          -- object lock requested at initiate
    initiated_at   timestamptz  NOT NULL DEFAULT now(),
    expires_at     timestamptz  NOT NULL DEFAULT now() + interval '7 days'
);
CREATE INDEX uploads_bucket_idx ON uploads (bucket_id, initiated_at);
CREATE INDEX uploads_expiry_idx ON uploads (expires_at);

CREATE TABLE upload_parts (
    upload_id    uuid         NOT NULL REFERENCES uploads (upload_id) ON DELETE CASCADE,
    part_number  integer      NOT NULL CHECK (part_number BETWEEN 1 AND 10000),
    etag         text         NOT NULL DEFAULT '',
    size         bigint       NOT NULL CHECK (size >= 0),
    chunks       jsonb        NOT NULL,            -- []ChunkRef
    encryption   jsonb        NOT NULL DEFAULT '{}',
    updated_at   timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (upload_id, part_number)
);

-- ---------------------------------------------------------------------------
-- Deletion queue, repair, accounting, audit
-- ---------------------------------------------------------------------------

CREATE SEQUENCE deletion_queue_id_seq;

CREATE TABLE deletion_queue (
    deletion_id   bigint       PRIMARY KEY DEFAULT nextval('deletion_queue_id_seq'),
    bucket_id     uuid         NOT NULL,
    key           text         NOT NULL,
    version_id    uuid         NOT NULL,
    manifest_hash bytea,
    reason        text         NOT NULL,
    created_at    timestamptz  NOT NULL DEFAULT now(),
    due_at        timestamptz  NOT NULL DEFAULT now() + interval '24 hours',
    -- GC progress: set when a collector starts, plus one entry per agent
    -- endpoint that has acknowledged deletion. Makes a crash-retry cheap
    -- (acknowledged endpoints are skipped, never re-deleted).
    started_at      timestamptz,
    acked_endpoints text[]       NOT NULL DEFAULT '{}'
);
CREATE INDEX deletion_queue_due_idx ON deletion_queue (due_at);

CREATE TABLE repair_jobs (
    job_id        uuid         PRIMARY KEY,
    type          text         NOT NULL CHECK (type IN ('local','geo','corruption','rebalance')),
    shard_set_id  uuid         NOT NULL REFERENCES shard_sets (shard_set_id) ON DELETE CASCADE,
    generation    bigint       NOT NULL,
    params        jsonb        NOT NULL,
    sources       jsonb        NOT NULL DEFAULT '[]',
    targets       jsonb        NOT NULL DEFAULT '[]',
    state         text         NOT NULL DEFAULT 'queued'
                    CHECK (state IN ('queued','leased','done','failed')),
    worker        text,
    lease_until   timestamptz,
    max_mbps      integer      NOT NULL DEFAULT 200,
    deadline      timestamptz,
    created_at    timestamptz  NOT NULL DEFAULT now(),
    finished_at   timestamptz
);
CREATE INDEX repair_jobs_ready_idx ON repair_jobs (state, created_at) WHERE state = 'queued';

CREATE TABLE shard_status (
    agent_id      uuid         NOT NULL REFERENCES agents (agent_id) ON DELETE CASCADE,
    shard_set_id  uuid         NOT NULL,
    slot          integer      NOT NULL,
    state         text         NOT NULL CHECK (state IN ('OK','MISSING','CORRUPT')),
    updated_at    timestamptz  NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, shard_set_id, slot)
);
CREATE INDEX shard_status_corrupt_idx ON shard_status (state) WHERE state <> 'OK';

CREATE TABLE usage_hourly (
    hour_start        timestamptz  NOT NULL,
    project_id        uuid         NOT NULL REFERENCES projects (project_id) ON DELETE CASCADE,
    bucket_id         uuid         NOT NULL REFERENCES buckets (bucket_id) ON DELETE CASCADE,
    storage_byte_hours numeric     NOT NULL DEFAULT 0,
    objects_total     bigint       NOT NULL DEFAULT 0,
    objects_non_empty bigint       NOT NULL DEFAULT 0,
    ingress_bytes     bigint       NOT NULL DEFAULT 0,
    egress_bytes      bigint       NOT NULL DEFAULT 0,
    PRIMARY KEY (hour_start, project_id, bucket_id)
);

CREATE TABLE audit_log (
    audit_id    bigserial    PRIMARY KEY,
    at          timestamptz  NOT NULL DEFAULT now(),
    tenant_id   uuid,
    project_id  uuid,
    access_key  text,
    action      text         NOT NULL,
    resource    text         NOT NULL,             -- CRN
    allowed     boolean      NOT NULL,
    reason      text         NOT NULL DEFAULT '',
    source_ip   inet,
    request_id  text
);
CREATE INDEX audit_log_at_idx ON audit_log (at DESC);
CREATE INDEX audit_log_tenant_idx ON audit_log (tenant_id, at DESC);

COMMIT;

-- ===========================================================================
-- APPENDIX — embedded dev engine physical layout (NOT normative)
-- ===========================================================================
--
-- The embedded engine (internal/storage) is a single-writer, write-ahead-logged
-- ordered key-value store. It exists so `fass-coordinator` runs with zero external
-- dependencies in dev/eval; production uses the DDL above. It is explicitly not a
-- general-purpose database:
--
--   * durability: each Update is one CRC32C-framed WAL record, fsync'd before it
--     is applied in memory; a torn tail frame is truncated on Open; snapshots
--     bound recovery time and truncate the WAL;
--   * concurrency: one process owns the directory (flock on LOCK); readers are
--     concurrent, writers serialised;
--   * limits: metadata-only volume; no range queries beyond prefix scans.
--
-- Keys are NUL-separated ("\0") and end with a separator so prefix scans cannot
-- collide across buckets/keys. Integers are big-endian. Values are JSON records
-- (isomorphic to the table rows above) except manifest blobs, which are
--   byte version | uint64 uncompressed_len | flate(JSON(contract.Manifest)).
--
-- Space                     Key                                    Value
-- ------------------------  -------------------------------------  ------------------------------
-- tenants                   tenant_id                              Tenant
-- buckets                   bucket_name                            Bucket (+ ACL, lifecycle)
-- bucket_ids                bucket_id                              bucket_name
-- objects_latest            bucket_id\0key\0                       latestRecord
-- objects_versions          bucket_id\0key\0seq                    versionRecord
-- object_version_ids        bucket_id\0key\0version_id\0           versionRecord
-- manifest_blobs            sha256_hex                             compressed manifest
-- uploads                   upload_id                              uploadRecord
-- uploads_index             bucket_id\0upload_id\0                 uploadRecord
-- upload_parts              upload_id\0part_number(4B BE)          partRecord
-- deletions                 seq(8B BE)                             DeletionItem
-- counters                  name                                   uint64 BE
-- access_keys               access_key_id                          AccessKey
-- iam_policies              policy_id                              Policy
-- bucket_policies           bucket_name                            Policy
-- swarms                    swarm_id                               Swarm
-- nexuses                   nexus_id                               Nexus
-- nodes                     node_id                                Node
-- agents                    agent_id                               Agent
-- agents_by_pubkey          base64(public_key)                     agent_id
-- agents_by_location        node_id\0disk_id                       agent_id
-- rings                     ring_id                                Ring
-- redundancy_classes        rc_id                                  RedundancyClass
-- shard_status              agent_id\0shard_set_id\0slot(4B BE)    shardStatusRecord
-- meta                      schema_version                         decimal ASCII
--
-- Field mapping notes (why a JSON field is not always a column of the same name):
--   * Bucket.acl                  -> bucket_acls (one row per bucket)
--   * versionRecord.tags          -> object_tags (one row per tag)
--   * versionRecord.acl           -> object_acls (one row per version)
--   * versionRecord.retention     -> object_versions.retention_mode/retain_until/legal_hold
--   * uploadRecord.meta           -> flattened into uploads.* (version_id, chunk_size, ...)
--   * RedundancyClass.params      -> redundancy_classes.geo_n/geo_k/local_n/local_k
--   * Agent.ring_ids              -> ring_agents (agents may belong to several rings)
--   * Tenant.key_seed             -> tenants.key_seed_wrapped (ciphertext at rest)
--   * AccessKey.secret            -> access_keys.secret_wrapped (ciphertext at rest)
--   * Bucket.lifecycle            -> buckets.lifecycle_xml
--   * latestRecord.version_id     -> objects.latest_version_id
--   * latestRecord.delete_marker  -> objects.is_delete_marker
--   * uploadRecord.created_at     -> uploads.initiated_at
--   * Ring.capacity               -> rings.capacity_bytes
--   * Agent.last_seen             -> agents.last_seen_at
--   * Agent.state_changed         -> agents.state_changed_at
--   * Agent.secret_expires        -> agents.secret_expires_at
--
-- Migrations are numbered and applied on boot (internal/storage/migrate.go);
-- the PostgreSQL column `schema_migrations.version` is the same number.

-- ===========================================================================
-- APPENDIX: PostgreSQL adapter physical layout (ADR-3b, v1)
-- ===========================================================================
--
-- The adapter (internal/storage/postgres) implements storage.Store with:
--
--   CREATE TABLE kv (
--       space text  NOT NULL,
--       key   bytea NOT NULL,      -- bytea, not text: coordinator keys are
--                                  -- NUL-separated (bucket\0key\0seq) and
--                                  -- PostgreSQL text rejects 0x00. bytea also
--                                  -- gives memcmp ordering, so ordered scans and
--                                  -- prefix ranges are identical to the embedded
--                                  -- engine.
--       value jsonb NOT NULL,      -- entity record (JSON). The few binary
--                                  -- records (counters) are stored as
--                                  -- {"__fass_bytes_base64__":"..."}; the
--                                  -- wrapper is internal to the adapter.
--       PRIMARY KEY (space, key)   -- B-tree; every access is a point get or a
--                                  -- bounded range (key >= prefix AND key < next(prefix))
--   ) WITH (fillfactor = 90);
--
--   CREATE TABLE blobs (
--       hash bytea PRIMARY KEY,    -- SHA-256 of the canonical manifest JSON
--       data bytea NOT NULL        -- version byte + uint64 length + flate page
--   );
--
-- Access paths (EXPLAIN-asserted in internal/storage/postgres/parity_test.go):
--   point get      SELECT value FROM kv WHERE space=$1 AND key=$2 [FOR UPDATE]
--   version range  ... WHERE space=$1 AND key >= $2 AND key < $3 ORDER BY key
--   prefix list    ... WHERE space=$1 AND key >= $2 AND key < $3 ORDER BY key
-- A sequential scan of kv is a test failure, not a performance regression.
--
-- Key families (space -> key) and their value record are listed in the embedded
-- appendix above; both backends encode the same bytes. Maximum composite key
-- (versions family: 1024-byte object key + UUID bucket id + 19-digit seq) is
-- asserted < 2048 bytes, well under the B-tree entry limit (~2704 bytes).
--
-- Locking: a write transaction takes SELECT ... FOR UPDATE row locks as records
-- are read, in the order the meta callback reads them. The commit path is
-- documented and tested to read bucket -> latest -> version-id -> counters in
-- that order (same order for every writer), so concurrent commits to one key
-- serialize instead of deadlocking. The adapter retries a transaction at most
-- three times on PostgreSQL serialization failures/deadlocks and surfaces every
-- other error to the caller.
--
-- Bloat: kv is a high-churn table (version deletes rewrite latest rows and add
-- tombstones forever). The migration sets aggressive autovacuum
-- (scale_factor 0.02/0.01, cost_limit 2000); see docs/09-deployment.md for the
-- operational guidance and the untested HA risks.
