-- Extend the audit action check with the GitHub App's push-signing action.
--
-- SQLite cannot alter a CHECK constraint, so rebuild the table in place — the
-- same approach as 0002 and 0003, and for the same reason: `action` is a closed
-- enum in `src/schemas/audit.ts` and the database is where that closure is
-- actually enforced. Without this the first webhook-signed push writes nothing
-- and the audit trail silently stops at the interesting event.
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
            'subject_revoke',
            'webhook_sign'
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
