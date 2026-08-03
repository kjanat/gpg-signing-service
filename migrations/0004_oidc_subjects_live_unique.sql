-- Force the (issuer, subject_prefix) uniqueness index to be scoped to live rows.
--
-- 0003 was edited in place to add `WHERE revoked_at IS NULL`, which is correct
-- for a database that has never applied it. It does nothing for one that has:
-- D1 tracks applied migrations by filename and will not re-run 0003, and even
-- re-running it would not help, because `CREATE UNIQUE INDEX IF NOT EXISTS` is
-- a no-op when an index of that name exists — it never compares definitions.
--
-- So a database migrated before that edit still carries an index spanning
-- revoked rows, and revoking a trust still locks that identity out for good.
-- Dropping first is what makes the change actually apply. On a fresh database
-- this re-creates an identical index, so it is safe to run either way.
DROP INDEX IF EXISTS idx_oidc_subjects_issuer_prefix;

CREATE UNIQUE INDEX idx_oidc_subjects_issuer_prefix
ON oidc_subjects (issuer, subject_prefix) WHERE revoked_at IS NULL;
