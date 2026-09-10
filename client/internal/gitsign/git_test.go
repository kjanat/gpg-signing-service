package gitsign

import (
	"strings"
	"testing"
)

// The scan abandons the walk at the first hit, which is what keeps an
// unbounded history from being read into memory.
func TestReadBatchStopsWhereAsked(t *testing.T) {
	stream := "1111 commit 5\nfirst\n2222 commit 6\nsecond\n"

	var seen []string
	stopped, err := readBatch(strings.NewReader(stream), func(object batchObject) (bool, error) {
		seen = append(seen, object.sha+":"+string(object.raw))
		return true, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !stopped {
		t.Error("expected the scan to report that it stopped early")
	}
	if len(seen) != 1 || seen[0] != "1111:first" {
		t.Errorf("expected only the first record, got %v", seen)
	}
}

func TestReadBatchReadsEveryRecord(t *testing.T) {
	stream := "1111 commit 5\nfirst\n2222 commit 6\nsecond\n"

	var seen []string
	stopped, err := readBatch(strings.NewReader(stream), func(object batchObject) (bool, error) {
		seen = append(seen, string(object.raw))
		return false, nil
	})
	if err != nil || stopped {
		t.Fatalf("unexpected result: stopped=%v err=%v", stopped, err)
	}
	if len(seen) != 2 || seen[0] != "first" || seen[1] != "second" {
		t.Errorf("expected both records, got %v", seen)
	}
}

// "<oid> missing" is a two-field record, and calling it a parser disagreement
// sends the operator looking in the wrong place.
func TestReadBatchNamesAMissingObject(t *testing.T) {
	_, err := readBatch(strings.NewReader("deadbeef missing\n"), func(batchObject) (bool, error) {
		return false, nil
	})
	if err == nil || !strings.Contains(err.Error(), "not in the object store") {
		t.Fatalf("expected a missing-object error, got %v", err)
	}
}

func TestReadBatchRejectsAnUnreadableHeader(t *testing.T) {
	_, err := readBatch(strings.NewReader("nonsense here for you\n"), func(batchObject) (bool, error) {
		return false, nil
	})
	if err == nil || !strings.Contains(err.Error(), "unexpected header") {
		t.Fatalf("expected a header error, got %v", err)
	}
}
