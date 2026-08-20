package gitsign

import (
	"strings"
	"testing"
)

// commitSHA stands in for the merge being rewritten.
const commitSHA = "3333333333333333333333333333333333333333"

// mergeWithTag is a merge commit whose mergetag names its second parent.
func mergeWithTag() []byte {
	return rawCommit(append(mergeHeader(), mergeTagHeaderLines(parentTwo, "v1")...), "merge\n")
}

// mergeHeader is the part of a merge commit's header that comes before any
// mergetag: the tree, both parents, and the idents.
func mergeHeader() []string {
	return []string{
		"tree " + treeSHA,
		"parent " + parentOne,
		"parent " + parentTwo,
		testAuthor,
		strings.Replace(testAuthor, "author", "committer", 1),
	}
}

// A mergetag embeds a signed tag object naming the commit it merged. When that
// commit is rewritten the header keeps the old SHA, and nothing else in the run
// would tell the operator.
func TestReportStaleMergetagWarnsOnce(t *testing.T) {
	var out strings.Builder
	s := &session{opts: Options{Out: &out}, result: &Result{}}

	s.reportStaleMergetag(mergeWithTag(), commitSHA, map[string]bool{parentTwo: true})

	if len(s.result.Warnings) != 1 {
		t.Fatalf("expected one warning, got %v", s.result.Warnings)
	}
	if !strings.Contains(out.String(), "mergetag naming "+short(parentTwo)) {
		t.Errorf("expected the warning to name the rewritten parent, got %q", out.String())
	}
}

// A merge is rewritten as soon as any one parent moves, but the embedded tag
// names one specific parent. Warning that the tag "matches no parent" when the
// tagged parent never moved sends the operator hunting for damage that is not
// there.
func TestReportStaleMergetagIgnoresAnUntaggedParent(t *testing.T) {
	var out strings.Builder
	s := &session{opts: Options{Out: &out}, result: &Result{}}

	s.reportStaleMergetag(mergeWithTag(), commitSHA, map[string]bool{parentOne: true})

	if len(s.result.Warnings) != 0 || out.String() != "" {
		t.Errorf("the tagged parent did not move, so the mergetag is still accurate; got %v and %q",
			s.result.Warnings, out.String())
	}
}

// octopusWithTags is a merge of two signed tags, each embedded under its own
// mergetag header the way git writes an octopus merge.
func octopusWithTags() []byte {
	header := append(mergeHeader(), mergeTagHeaderLines(parentOne, "v1")...)
	return rawCommit(append(header, mergeTagHeaderLines(parentTwo, "v2")...), "octopus\n")
}

// go-git v6 gives every mergetag header its own ExtraHeader entry, where v5
// folded them into a single field. Checking only the first tag would leave an
// octopus merge's later tags unreported, so each embedded tag is consulted.
func TestReportStaleMergetagCoversEveryEmbeddedTag(t *testing.T) {
	var out strings.Builder
	s := &session{opts: Options{Out: &out}, result: &Result{}}

	s.reportStaleMergetag(octopusWithTags(), commitSHA, map[string]bool{parentTwo: true})

	if len(s.result.Warnings) != 1 {
		t.Fatalf("expected one warning, got %v", s.result.Warnings)
	}
	if !strings.Contains(out.String(), "mergetag naming "+short(parentTwo)) {
		t.Errorf("expected the second embedded tag to be reported, got %q", out.String())
	}
}

// An ordinary commit has no mergetag to go stale, so the run must stay quiet.
func TestReportStaleMergetagIsSilentWithoutOne(t *testing.T) {
	var out strings.Builder
	s := &session{opts: Options{Out: &out}, result: &Result{}}

	plain := rawCommit([]string{"tree " + treeSHA, "parent " + parentOne, testAuthor}, "plain\n")
	s.reportStaleMergetag(plain, commitSHA, map[string]bool{parentOne: true})

	if len(s.result.Warnings) != 0 || out.String() != "" {
		t.Errorf("expected no warning, got %v and %q", s.result.Warnings, out.String())
	}
}
