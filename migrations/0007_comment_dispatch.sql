-- The GitHub App's comment-dispatch path records every `issue_comment` delivery
-- that reached a decision, so a workflow run this service started — or refused
-- to start — is answerable from the audit trail rather than only from the
-- Actions run list, which shows what ran and never what was declined.
--
-- SQLite cannot alter a CHECK constraint, so the table is rebuilt in place —
-- the same pattern as 0002, 0003, 0005 and 0006.
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
            'check_report',
            'comment_dispatch'
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
