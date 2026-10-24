-- 0002_sequences: lock-free monotonic sequences for version/deletion numbering.
--
-- The commit transaction used to read+write a single `kv` counter row with
-- FOR UPDATE, which serialised every metadata write in the cluster (measured:
-- ~32 ms average wait per lock acquisition in the load test, 7x inflation even
-- with no shared bucket). A native sequence is lock-free and non-transactional;
-- gaps are fine, and per-key ordering is preserved because callers allocate the
-- value after taking the key's latest-row lock.
CREATE SEQUENCE IF NOT EXISTS fass_version_seq AS bigint;
CREATE SEQUENCE IF NOT EXISTS fass_deletion_seq AS bigint;
