package client

import (
	"time"
)

// parseTimestamp converts an ISO 8601 timestamp string to time.Time.
// Returns zero time if parsing fails.
func parseTimestamp(ts string) time.Time {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return time.Time{}
	}
	return t
}
