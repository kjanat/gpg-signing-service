-- Audit logs table for tracking all signing operations
CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    request_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('sign', 'key_upload', 'key_rotate')),
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    key_id TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0,
    error_code TEXT,
    metadata TEXT
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_subject ON audit_logs (subject);
CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_logs (request_id);
CREATE INDEX IF NOT EXISTS idx_audit_key_id ON audit_logs (key_id);

-- Composite index for filtering by action and date range
CREATE INDEX IF NOT EXISTS idx_audit_action_timestamp ON audit_logs (
    action, timestamp DESC
);
