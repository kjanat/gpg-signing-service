-- The GitHub App's check-run reporter records what it published, so a verdict
-- this service stated about somebody's commit is reconstructable from the audit
-- trail rather than only from the check run itself — which an operator can see
-- and nobody can query.
--
-- SQLite cannot alter a CHECK constraint, so the table is rebuilt in place —
-- the same pattern as 0002, 0003 and 0005.
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
            'push_sign',
            'check_report'
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
