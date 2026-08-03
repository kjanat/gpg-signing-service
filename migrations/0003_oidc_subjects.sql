-- Trusted OIDC subjects: which CI identities may sign, and with which keys.
--
-- Without this, authentication stops at issuer + audience. Both are shared:
-- token.actions.githubusercontent.com issues tokens to every repository on
-- GitHub Actions, gitlab.com to every project there, and the audience is a
-- public string. Any of them could mint a token and sign.
--
-- The shape deliberately mirrors service_tokens, so an OIDC caller is a
-- first-class, revocable, key-scoped identity rather than a hardcoded string
-- in the Worker config.
CREATE TABLE IF NOT EXISTS oidc_subjects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    -- Issuer this subject must come from, pinned per row so a GitLab project
    -- cannot present a GitHub-shaped subject string, or vice versa.
    issuer TEXT NOT NULL,
    -- Matched as a delimiter-terminated prefix of the token's `sub`, so
    -- `repo:owner/name` does not also admit `repo:owner/name-evil`. A prefix
    -- that itself ends at a delimiter (`repo:owner/`) is owner-wide.
    subject_prefix TEXT NOT NULL,
    -- Comma-separated key-id allowlist; empty string means every key.
    key_ids TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked_at TEXT,
    last_used_at TEXT
);

-- Lookups are always "active rows for this issuer", then prefix-matched in
-- application code, because SQL cannot express the delimiter rule.
CREATE INDEX IF NOT EXISTS idx_oidc_subjects_issuer ON oidc_subjects (issuer);

CREATE UNIQUE INDEX IF NOT EXISTS idx_oidc_subjects_issuer_prefix
ON oidc_subjects (issuer, subject_prefix);

-- Extend the audit action check with subject lifecycle actions. SQLite cannot
-- alter a CHECK constraint, so rebuild the table in place (same approach as
-- 0002).
CREATE TABLE audit_logs_new (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    request_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (
        action IN (
            'sign',
            'key_upload',
            'key_rotate',
            'token_create',
            'token_revoke',
            'subject_create',
            'subject_revoke'
        )
    ),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    key_id TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    metadata TEXT
);

INSERT INTO audit_logs_new SELECT * FROM audit_logs;
DROP TABLE audit_logs;
ALTER TABLE audit_logs_new RENAME TO audit_logs;

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_logs (subject);
CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_logs (request_id);
CREATE INDEX IF NOT EXISTS idx_audit_key_id ON audit_logs (key_id);
CREATE INDEX IF NOT EXISTS idx_audit_action_timestamp ON audit_logs (
    action, timestamp DESC
);
