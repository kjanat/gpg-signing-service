package gitsign

import (
	"strings"
	"testing"
)

// A mergetag embeds a signed tag object naming the commit it merged. When that
// commit is rewritten the header keeps the old SHA, and nothing else in the run
// would tell the operator.
func TestReportStaleMergetagWarnsOnce(t *testing.T) {
	var out strings.Builder
	s := &session{opts: Options{Out: &out}, result: &Result{}}

	merge := rawCommit([]string{
		"tree " + treeSHA,
		"parent " + parentOne,
		"parent " + parentTwo,
		testAuthor,
		strings.Replace(testAuthor, "author", "committer", 1),
		"mergetag object " + parentTwo,
		" type commit",
		" tag v1",
		" tagger T <t@example.test> 1700000000 +0000",
		" ",
		" tag message",
	}, "merge\n")

	s.reportStaleMergetag(merge, parentOne)

	if len(s.result.Warnings) != 1 {
		t.Fatalf("expected one warning, got %v", s.result.Warnings)
	}
	if !strings.Contains(out.String(), "mergetag naming the pre-rewrite commit") {
		t.Errorf("expected the warning to name the cause, got %q", out.String())
	}
}

// An ordinary commit has no mergetag to go stale, so the run must stay quiet.
func TestReportStaleMergetagIsSilentWithoutOne(t *testing.T) {
	var out strings.Builder
	s := &session{opts: Options{Out: &out}, result: &Result{}}

	s.reportStaleMergetag(rawCommit([]string{"tree " + treeSHA, "parent " + parentOne, testAuthor}, "plain\n"), parentOne)

	if len(s.result.Warnings) != 0 || out.String() != "" {
		t.Errorf("expected no warning, got %v and %q", s.result.Warnings, out.String())
	}
}
