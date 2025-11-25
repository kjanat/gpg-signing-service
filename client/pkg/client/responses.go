package client

import (
	"encoding/json"
	"time"
)

// HealthStatus represents a service health check result.
type HealthStatus struct {
	Status     string    `json:"status"`
	Version    string    `json:"version"`
	Timestamp  time.Time `json:"timestamp"`
	KeyStorage bool      `json:"keyStorage"`
	Database   bool      `json:"database"`
}

// IsHealthy returns true if the service is healthy.
func (h *HealthStatus) IsHealthy() bool {
	return h.Status == "healthy"
}

// SignResult represents a successful signing operation.
type SignResult struct {
	Signature          string     `json:"signature"`
	RateLimitRemaining *int       `json:"rateLimitRemaining,omitempty"`
	RateLimitReset     *time.Time `json:"rateLimitReset,omitempty"`
}

// KeyInfo represents uploaded key information.
type KeyInfo struct {
	KeyID       string `json:"keyId"`
	Fingerprint string `json:"fingerprint"`
}

// KeyMetadata represents key listing information.
type KeyMetadata struct {
	KeyID       string    `json:"keyId"`
	Fingerprint string    `json:"fingerprint"`
	Algorithm   string    `json:"algorithm"`
	CreatedAt   time.Time `json:"createdAt"`
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
	ID        string          `json:"id"`
	Timestamp time.Time       `json:"timestamp"`
	RequestID string          `json:"requestId"`
	Action    string          `json:"action"`
	Issuer    string          `json:"issuer"`
	Subject   string          `json:"subject"`
	KeyID     string          `json:"keyId"`
	Success   bool            `json:"success"`
	ErrorCode *string         `json:"errorCode,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
}

// AuditResult represents audit query results.
type AuditResult struct {
	Logs  []AuditLog `json:"logs"`
	Count int        `json:"count"`
}
