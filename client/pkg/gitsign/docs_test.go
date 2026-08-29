package gitsign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// collapse folds every run of whitespace into one space.
//
// The guide hard-wraps at 80 columns and the error is one long line, so a
// literal comparison would only ever be testing where the paragraph broke.
func collapse(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// docs/cli.md quotes the empty-scan error verbatim, and quotes drift.
//
// It went stale exactly once already: the guide reproduced a version
// recommending `--base=origin/master`, which is the one value that cannot be
// right where this message prints. lastSigned is reachable only with an empty
// base *on the default branch*, so `origin/<default>` there is this branch's
// own remote tip rather than a fork point, and the range from it is whatever
// has not been pushed — usually nothing. A reader following the guide got an
// empty range and a second round of guessing.
//
// Nothing failed when the message was corrected and the guide was not, because
// a quotation is prose to every tool that reads it. This runs the real path and
// asserts the guide still contains what came out.
func TestCLIGuideQuotesTheCurrentEmptyScanError(t *testing.T) {
	dir, svc := serviceFixture(t)
	commit(t, dir, "first", foreignEmail)

	// No ScanLimit, so the scope reads "HEAD" — the form the guide quotes, and
	// the form a reader gets when they pass no flags at all.
	_, _, err := runEngine(t, dir, svc.api, Options{})
	if err == nil {
		t.Fatal("expected the base-resolution failure the guide documents")
	}

	// The CLI prefixes "sign-commit failed: " before printing; the guide shows
	// the whole line, so compare on the engine's half.
	message := collapse(err.Error())
	if !strings.Contains(message, "pass base explicitly") {
		t.Fatalf("not the failure this test is about: %v", err)
	}

	raw, readErr := os.ReadFile(filepath.Join("..", "..", "..", "docs", "cli.md"))
	if readErr != nil {
		t.Fatalf("reading docs/cli.md: %v", readErr)
	}
	guide := collapse(string(raw))

	if !strings.Contains(guide, message) {
		t.Errorf("docs/cli.md does not quote the error the engine now emits.\n\nemitted: %s\n\nUpdate the ```text block under \"What --base is\".", message)
	}

	// And the guide must not carry the suggestion the message deliberately
	// dropped, in the paragraph that tells the reader what to pass. Scoped to
	// that section because `--base=origin/master` is still correct one branch
	// over, where it names a real fork point, and the guide says so.
	section := sectionOf(t, string(raw), "#### What `--base` is", "#### Reading a failure")
	if strings.Contains(section, "`--base=origin/master` is the general answer") {
		t.Error("docs/cli.md still offers --base=origin/master as the general answer; on the default branch there is no branch point to borrow")
	}
	if !strings.Contains(collapse(section), "`--base=<sha>` — the commit just before the first one you want signed — is the general answer") {
		t.Error("docs/cli.md no longer states --base=<sha> as the general answer")
	}
}

// sectionOf returns the slice of doc between two headings.
func sectionOf(t *testing.T, doc, start, end string) string {
	t.Helper()

	from := strings.Index(doc, start)
	if from < 0 {
		t.Fatalf("docs/cli.md has no %q heading", start)
	}
	to := strings.Index(doc[from:], end)
	if to < 0 {
		t.Fatalf("docs/cli.md has no %q heading after %q", end, start)
	}
	return doc[from : from+to]
}
