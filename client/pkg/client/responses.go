package client

import (
	"encoding/json"
	"time"
)

// HealthStatus represents service health check result.
type HealthStatus struct {
	Status     string
	Version    string
	Timestamp  time.Time
	KeyStorage bool
	Database   bool
}

// IsHealthy returns true if the service is healthy.
func (h *HealthStatus) IsHealthy() bool {
	return h.Status == "healthy"
}

// SignResult represents a successful signing operation.
type SignResult struct {
	Signature          string
	RateLimitRemaining *int
	RateLimitReset     *time.Time
}

// KeyInfo represents uploaded key information.
type KeyInfo struct {
	KeyID       string
	Fingerprint string
	Algorithm   string
	UserID      string
}

// KeyMetadata represents key listing information.
type KeyMetadata struct {
	KeyID       string
	Fingerprint string
	Algorithm   string
	CreatedAt   time.Time
}

// AuditFilter configures audit log queries.
type AuditFilter struct {
	Limit     int
	Offset    int
	Action    string // "sign", "key_upload", "key_rotate"
	Subject   string
	StartDate time.Time
	EndDate   time.Time
}

// AuditLog represents a single audit log entry.
type AuditLog struct {
	ID        string
	Timestamp time.Time
	RequestID string
	Action    string
	Issuer    string
	Subject   string
	KeyID     string
	Success   bool
	ErrorCode *string
	Metadata  json.RawMessage
}

// AuditResult represents audit query results.
type AuditResult struct {
	Logs  []AuditLog
	Count int
}
