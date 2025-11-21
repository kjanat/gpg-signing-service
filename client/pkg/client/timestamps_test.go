package client

import (
	"testing"
	"time"
)

// TestParseTimestamp tests the parseTimestamp helper function
func TestParseTimestamp(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		wantZero bool
	}{
		{
			name:     "valid RFC3339 timestamp",
			input:    "2023-11-20T10:30:45Z",
			wantErr:  false,
			wantZero: false,
		},
		{
			name:     "valid RFC3339 with timezone",
			input:    "2023-11-20T10:30:45+02:00",
			wantErr:  false,
			wantZero: false,
		},
		{
			name:     "empty timestamp",
			input:    "",
			wantErr:  true,
			wantZero: true,
		},
		{
			name:     "invalid timestamp format",
			input:    "not-a-timestamp",
			wantErr:  true,
			wantZero: true,
		},
		{
			name:     "invalid timestamp format 2",
			input:    "2023-11-20 10:30:45",
			wantErr:  true,
			wantZero: true,
		},
		{
			name:     "another valid RFC3339 timestamp",
			input:    "2024-01-01T00:00:00Z",
			wantErr:  false,
			wantZero: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseTimestamp(tt.input)

			if tt.wantZero && !result.IsZero() {
				t.Errorf("expected zero time, got %v", result)
			}
			if !tt.wantZero && result.IsZero() {
				t.Errorf("expected non-zero time, got zero time")
			}
			if !tt.wantErr && tt.wantZero {
				t.Errorf("test case contradiction: wantErr=%v, wantZero=%v", tt.wantErr, tt.wantZero)
			}
		})
	}
}

// TestParseTimestampPrecision tests timestamp parsing precision
func TestParseTimestampPrecision(t *testing.T) {
	timestamp := "2023-11-20T10:30:45.123Z"
	result := parseTimestamp(timestamp)

	if result.IsZero() {
		t.Fatal("failed to parse timestamp with milliseconds")
	}

	// Verify year, month, day
	if result.Year() != 2023 || result.Month() != 11 || result.Day() != 20 {
		t.Errorf("date mismatch: got %d-%d-%d", result.Year(), result.Month(), result.Day())
	}

	// Verify hour, minute, second
	if result.Hour() != 10 || result.Minute() != 30 || result.Second() != 45 {
		t.Errorf("time mismatch: got %02d:%02d:%02d", result.Hour(), result.Minute(), result.Second())
	}
}

// TestParseTimestampRoundtrip tests parsing a timestamp from time format
func TestParseTimestampRoundtrip(t *testing.T) {
	now := time.Now().UTC()
	timestamp := now.Format(time.RFC3339)

	result := parseTimestamp(timestamp)

	if result.IsZero() {
		t.Fatal("failed to parse roundtrip timestamp")
	}

	// Verify they're approximately equal (allow 1 second difference for parsing)
	diff := now.Sub(result).Seconds()
	if diff < -1 || diff > 1 {
		t.Errorf("timestamp roundtrip mismatch: difference is %f seconds", diff)
	}
}

// TestParseTimestampEdgeCases tests edge cases for timestamp parsing
func TestParseTimestampEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{
			name:   "year 2000",
			input:  "2000-01-01T00:00:00Z",
			expect: "2000-01-01",
		},
		{
			name:   "leap year",
			input:  "2020-02-29T12:00:00Z",
			expect: "2020-02-29",
		},
		{
			name:   "new year",
			input:  "2024-01-01T00:00:00Z",
			expect: "2024-01-01",
		},
		{
			name:   "end of year",
			input:  "2023-12-31T23:59:59Z",
			expect: "2023-12-31",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseTimestamp(tt.input)
			dateStr := result.Format("2006-01-02")

			if dateStr != tt.expect {
				t.Errorf("expected date %q, got %q", tt.expect, dateStr)
			}
		})
	}
}

// TestParseTimestampConcurrency tests concurrent timestamp parsing
func TestParseTimestampConcurrency(t *testing.T) {
	timestamp := "2023-11-20T10:30:45Z"
	results := make(chan time.Time, 100)

	// Run 100 concurrent parses
	for i := 0; i < 100; i++ {
		go func() {
			results <- parseTimestamp(timestamp)
		}()
	}

	// Collect results and verify consistency
	firstResult := <-results
	for i := 1; i < 100; i++ {
		result := <-results
		if !result.Equal(firstResult) {
			t.Errorf("concurrent parse mismatch: got %v, expected %v", result, firstResult)
		}
	}
}

// BenchmarkParseTimestamp benchmarks timestamp parsing
func BenchmarkParseTimestamp(b *testing.B) {
	timestamp := "2023-11-20T10:30:45Z"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseTimestamp(timestamp)
	}
}

// BenchmarkParseTimestampWithMillis benchmarks timestamp parsing with milliseconds
func BenchmarkParseTimestampWithMillis(b *testing.B) {
	timestamp := "2023-11-20T10:30:45.123456Z"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = parseTimestamp(timestamp)
	}
}
