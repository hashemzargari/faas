-- 0001_kv: metadata row store + immutable content-addressed manifest blobs.
--
-- kv mirrors the coordinator's ordered key/value model exactly:
--   space   logical table family ("buckets", "objects_versions", ...)
--   key     composite key, NUL-separated; bytea because S3 object keys and the
--           coordinator's encoding may contain 0x00, which PostgreSQL text forbids
--   value   JSON document for the record family; see value_codec.go for the
--           escape used by the few binary records (counters)
--
-- The primary key is a B-tree over (space, key): every production access path is
-- a point get or a bounded range scan (key >= prefix AND key < next(prefix)).
-- blobs holds compressed, content-addressed manifest pages; they are immutable
-- and never go through JSONB (a 1 MiB TOAST round-trip would be pointless).
CREATE TABLE IF NOT EXISTS kv (
    space text  NOT NULL,
    key   bytea NOT NULL,
    value jsonb NOT NULL,
    PRIMARY KEY (space, key)
) WITH (fillfactor = 90);

CREATE TABLE IF NOT EXISTS blobs (
    hash bytea NOT NULL PRIMARY KEY,
    data bytea NOT NULL
);

-- High-churn tables: version deletes and tombstones rewrite kv rows constantly.
-- Aggressive autovacuum on the insert/update/delete-heavy kv table is deliberate:
-- the failure mode of the default settings is slow, mysterious degradation after
-- months of operation. Tune scale_factor 0.02 and cost limits per cluster size;
-- these are the documented starting values.
ALTER TABLE kv SET (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_analyze_scale_factor = 0.01,
    autovacuum_vacuum_cost_limit = 2000
);
