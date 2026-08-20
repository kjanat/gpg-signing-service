package gitsign

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/kjanat/gpg-signing-service/client/pkg/client"
)

func TestRunSignsEveryCommitInRange(t *testing.T) {
	dir, svc := serviceFixture(t)
	base := head(t, dir)
	commit(t, dir, "first", serviceEmail)
	commit(t, dir, "second", serviceEmail)

	result, out, err := runEngine(t, dir, svc.api, Options{Base: base})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Signed != 2 || result.Scanned != 2 {
		t.Fatalf("expected 2 of 2 signed, got %d of %d", result.Signed, result.Scanned)
	}
	if !result.RefUpdated {
		t.Error("expected the run to move HEAD")
	}
	if result.Pushed {
		t.Error("the engine must never push")
	}
	if got := head(t, dir); got != result.Tip {
		t.Errorf("expected HEAD at %s, got %s", result.Tip, got)
	}
	for _, rewrite := range result.Rewrites {
		if rewrite.Mark != MarkSigned {
			t.Errorf("expected every commit signed, got %s on %s", rewrite.Mark, rewrite.Commit)
		}
	}
	if !strings.Contains(out, "Signed 2 of 2 commit(s)") {
		t.Errorf("expected a summary line, got:\n%s", out)
	}
	if !strings.Contains(out, "Nothing was pushed") {
		t.Errorf("expected the run to say it did not push, got:\n%s", out)
	}
	assertVerifies(t, dir, svc, result.Tip)
}

// A rewritten commit's descendants must be rewritten too, or they would still
// point at the pre-signature parent.
func TestRunReparentsDescendantsOfSignedCommits(t *testing.T) {
	dir, svc := serviceFixture(t)
	base := head(t, dir)
	commit(t, dir, "mine", serviceEmail)
	commit(t, dir, "theirs", foreignEmail)

	result, _, err := runEngine(t, dir, svc.api, Options{Base: base})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := marks(result)
	if len(got) != 2 || !strings.HasPrefix(got[0], "signed ") || !strings.HasPrefix(got[1], "reparent ") {
		t.Fatalf("expected a signed commit then a reparented child, got %v", got)
	}
	if result.Signed != 1 {
		t.Errorf("expected 1 signature, got %d", result.Signed)
	}
}

// Signing every commit in the range must remap merge parents independently:
// only part of a merge's ancestry may have been rewritten.
func TestRunRemapsBothMergeParents(t *testing.T) {
	dir, svc := serviceFixture(t)
	base := head(t, dir)

	git(t, dir, nil, "checkout", "-b", "side")
	side := commit(t, dir, "side", serviceEmail)
	git(t, dir, nil, "checkout", "master")
	commit(t, dir, "main", serviceEmail)
	git(t, dir, identity(serviceEmail), "merge", "--no-ff", "--no-edit", side)

	result, _, err := runEngine(t, dir, svc.api, Options{Base: base})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rewritten := make(map[string]string, len(result.Rewrites))
	for _, rewrite := range result.Rewrites {
		rewritten[rewrite.Commit] = rewrite.NewCommit
	}
	if len(rewritten) != 3 {
		t.Fatalf("expected the merge and both sides rewritten, got %d", len(rewritten))
	}

	parents := strings.Fields(git(t, dir, nil, "rev-list", "--parents", "-n", "1", result.Tip))[1:]
	if len(parents) != 2 {
		t.Fatalf("expected the tip to stay a merge, got parents %v", parents)
	}
	for _, parent := range parents {
		if !isRewrittenSHA(rewritten, parent) {
			t.Errorf("parent %s was not remapped to a rewritten commit", parent)
		}
	}
	assertVerifies(t, dir, svc, result.Tip)
}

// Rewriting a commit that already carries a signature destroys an attestation,
// so it needs an explicit opt-in.
func TestRunBlocksResignWithoutOptIn(t *testing.T) {
	dir, svc := serviceFixture(t)
	base := head(t, dir)
	foreign := newEntity(t, foreignName, foreignEmail)
	commit(t, dir, "mine", serviceEmail)
	commitSignedBy(t, dir, "theirs", foreignEmail, foreign)
	before := head(t, dir)

	result, out, err := runEngine(t, dir, svc.api, Options{Base: base})

	var blocked *ResignError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected a ResignError, got %v", err)
	}
	if len(blocked.Resign) != 1 || blocked.Stale != 2 {
		t.Errorf("expected 1 of 2 stale commits already signed, got %d of %d", len(blocked.Resign), blocked.Stale)
	}
	if !strings.Contains(out, "would drop the signature on") {
		t.Errorf("expected the dry-run report to name the destructive case, got:\n%s", out)
	}
	if !strings.Contains(err.Error(), "allow_resign") || !strings.Contains(err.Error(), "--allow-resign") {
		t.Errorf("expected the remedy in the error, got: %v", err)
	}
	if result != nil && result.RefUpdated {
		t.Error("a blocked run must not move HEAD")
	}
	if head(t, dir) != before {
		t.Error("HEAD moved despite the guard")
	}
}

// With the opt-in, the same run strips the foreign signature and says so.
func TestRunStripsForeignSignatureWithOptIn(t *testing.T) {
	dir, svc := serviceFixture(t)
	base := head(t, dir)
	foreign := newEntity(t, foreignName, foreignEmail)
	commit(t, dir, "mine", serviceEmail)
	commitSignedBy(t, dir, "theirs", foreignEmail, foreign)

	result, out, err := runEngine(t, dir, svc.api, Options{Base: base, AllowResign: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := marks(result)
	if len(got) != 2 || !strings.HasPrefix(got[1], "stripped ") {
		t.Fatalf("expected the foreign commit marked stripped, got %v", got)
	}
	if !strings.Contains(out, "Dropped the signature on 1 commit(s)") {
		t.Errorf("expected a warning about the destroyed signature, got:\n%s", out)
	}
	if !strings.Contains(out, "sign_others") {
		t.Errorf("expected the remedy in the warning, got:\n%s", out)
	}
}

// --sign-others turns the same foreign commit into one this key signs.
func TestRunSignsOthersOnRequest(t *testing.T) {
	dir, svc := serviceFixture(t)
	base := head(t, dir)
	commit(t, dir, "theirs", foreignEmail)

	result, _, err := runEngine(t, dir, svc.api, Options{Base: base, SignOthers: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Signed != 1 {
		t.Fatalf("expected the foreign commit signed, got %d", result.Signed)
	}
	assertVerifies(t, dir, svc, result.Tip)
}

func TestRunReportsNothingToSignOnceEverythingVerifies(t *testing.T) {
	dir, svc := serviceFixture(t)
	base := head(t, dir)
	commit(t, dir, "first", serviceEmail)

	if _, _, err := runEngine(t, dir, svc.api, Options{Base: base}); err != nil {
		t.Fatalf("unexpected error on the first run: %v", err)
	}

	result, out, err := runEngine(t, dir, svc.api, Options{Base: base})
	if err != nil {
		t.Fatalf("unexpected error on the second run: %v", err)
	}
	if len(result.Rewrites) != 0 || result.RefUpdated {
		t.Errorf("expected the second run to be a no-op, got %v", marks(result))
	}
	if !strings.Contains(out, "Nothing to sign") {
		t.Errorf("expected a no-op message, got:\n%s", out)
	}
}

// A base that resolves to HEAD selects nothing, and the reason is specific
// enough to be worth its own message.
func TestRunReportsEmptyRangeWhenBaseIsHead(t *testing.T) {
	dir, svc := serviceFixture(t)

	result, out, err := runEngine(t, dir, svc.api, Options{Base: head(t, dir)})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Scanned != 0 || result.RefUpdated {
		t.Errorf("expected an empty range, got %d commit(s)", result.Scanned)
	}
	if !strings.Contains(out, "which is HEAD itself") {
		t.Errorf("expected the exclusive-bound explanation, got:\n%s", out)
	}
}

// A range of commits by identities the key does not carry signs nothing, and
// silence would read as success.
func TestRunWarnsWhenEveryCommitBelongsToOthers(t *testing.T) {
	dir, svc := serviceFixture(t)
	base := head(t, dir)
	commit(t, dir, "theirs", foreignEmail)

	result, out, err := runEngine(t, dir, svc.api, Options{Base: base})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Signed != 0 || result.RefUpdated {
		t.Errorf("expected nothing signed, got %d", result.Signed)
	}
	if !strings.Contains(out, "sign_others") {
		t.Errorf("expected the remedy in the warning, got:\n%s", out)
	}
}

// On the default branch with no base, the range starts at the last commit this
// key already verifies.
func TestRunResolvesBaseFromTheLastSignedCommit(t *testing.T) {
	dir, svc := serviceFixture(t)
	base := head(t, dir)
	commit(t, dir, "first", serviceEmail)

	first, _, err := runEngine(t, dir, svc.api, Options{Base: base})
	if err != nil {
		t.Fatalf("unexpected error on the first run: %v", err)
	}
	commit(t, dir, "second", serviceEmail)

	result, _, err := runEngine(t, dir, svc.api, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Base != first.Tip {
		t.Errorf("expected the base at the last signed commit %s, got %s", short(first.Tip), short(result.Base))
	}
	if result.Scanned != 1 || result.Signed != 1 {
		t.Errorf("expected only the new commit signed, got %d of %d", result.Signed, result.Scanned)
	}
}

// Without a signed commit to anchor on, guessing a base would silently rewrite
// the whole branch.
func TestRunRefusesWhenNoCommitVerifies(t *testing.T) {
	dir, svc := serviceFixture(t)
	commit(t, dir, "first", foreignEmail)

	_, _, err := runEngine(t, dir, svc.api, Options{ScanLimit: 5})
	if err == nil || !strings.Contains(err.Error(), "pass base explicitly") {
		t.Fatalf("expected a base-resolution failure, got %v", err)
	}
	if !strings.Contains(err.Error(), "the last 5 commit(s)") {
		t.Errorf("expected the scan bound named in the error, got: %v", err)
	}
}

// A scan limit only means something when the base is being scanned for, so a
// discarded one has to be visible.
func TestRunWarnsWhenScanLimitIsDiscarded(t *testing.T) {
	dir, svc := serviceFixture(t)
	base := head(t, dir)

	_, out, err := runEngine(t, dir, svc.api, Options{Base: base, ScanLimit: 10})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "scan-limit=10 was discarded") {
		t.Errorf("expected a discard warning, got:\n%s", out)
	}
}

func TestRunRejectsDetachedHead(t *testing.T) {
	dir, svc := serviceFixture(t)
	git(t, dir, nil, "checkout", "--detach")

	_, _, err := runEngine(t, dir, svc.api, Options{Base: head(t, dir)})
	if err == nil || !strings.Contains(err.Error(), "HEAD is detached") {
		t.Fatalf("expected a detached-HEAD refusal, got %v", err)
	}
}

func TestRunRejectsNegativeScanLimit(t *testing.T) {
	dir, svc := serviceFixture(t)

	_, _, err := runEngine(t, dir, svc.api, Options{ScanLimit: -1})
	if err == nil || !strings.Contains(err.Error(), "must not be negative") {
		t.Fatalf("expected a validation error, got %v", err)
	}
}

// A commit this key covers but cannot verify is re-signed, not stripped, and
// the dry-run report has to draw that distinction before anything is written.
func TestRunReportsResignForCommitsTheKeyCovers(t *testing.T) {
	dir, svc := serviceFixture(t)
	base := head(t, dir)
	foreign := newEntity(t, foreignName, foreignEmail)
	// Committed under the service's own address, but signed by a key the
	// service does not hold.
	commitSignedBy(t, dir, "mine but foreign-signed", serviceEmail, foreign)

	_, out, err := runEngine(t, dir, svc.api, Options{Base: base})

	var blocked *ResignError
	if !errors.As(err, &blocked) {
		t.Fatalf("expected a ResignError, got %v", err)
	}
	if !strings.Contains(out, "would re-sign") {
		t.Errorf("expected a re-sign report line, got:\n%s", out)
	}
	if !strings.Contains(out, "signed by a key this service does not carry") {
		t.Errorf("expected gpg's own reason in the report, got:\n%s", out)
	}
}

// The merge-base path is what a feature branch takes with no --base: the range
// starts where the branch forked from origin/<default-branch>.
func TestRunResolvesBaseFromTheMergeBase(t *testing.T) {
	dir, svc := serviceFixture(t)
	fork := head(t, dir)
	// Stand in for the fetched remote branch the fork point is measured against.
	git(t, dir, nil, "update-ref", "refs/remotes/origin/master", fork)
	git(t, dir, nil, "checkout", "-b", "feature")
	commit(t, dir, "feature work", serviceEmail)

	result, out, err := runEngine(t, dir, svc.api, Options{})
	if err != nil {
		t.Fatalf("unexpected error: %v\n%s", err, out)
	}

	if result.Base != fork {
		t.Errorf("expected the range to start at the fork point %s, got %s", short(fork), short(result.Base))
	}
	if result.Signed != 1 || result.Scanned != 1 {
		t.Fatalf("expected 1 of 1 signed, got %d of %d", result.Signed, result.Scanned)
	}
	assertVerifies(t, dir, svc, result.Tip)
}

// git names the signature header after the repository's hash algorithm. Left
// alone, a sha256 repository fails at the post-signing verification with an
// empty detail, long after the cause is visible.
func TestRunRefusesASHA256Repository(t *testing.T) {
	requireGit(t)

	entity := newEntity(t, serviceName, serviceEmail)
	svc := &fixture{entity: entity, api: newService(t, entity)}

	dir := t.TempDir()
	git(t, dir, nil, "init", "--initial-branch=master", "--object-format=sha256")
	git(t, dir, nil, "config", "commit.gpgsign", "false")
	commit(t, dir, "root", serviceEmail)
	base := head(t, dir)
	commit(t, dir, "first", serviceEmail)

	_, _, err := runEngine(t, dir, svc.api, Options{Base: base})
	if err == nil {
		t.Fatal("expected a sha256 repository to be refused")
	}
	if !strings.Contains(err.Error(), "sha256") || !strings.Contains(err.Error(), "gpgsig-sha256") {
		t.Errorf("expected the error to name the object format and the header it needs, got: %v", err)
	}
	if got := head(t, dir); got == "" {
		t.Error("expected HEAD to be untouched")
	}
}

// movingSigner commits to the branch the first time it is asked for a
// signature, which is the race updateRef's compare-and-swap exists to catch.
type movingSigner struct {
	Signer
	t    *testing.T
	dir  string
	done bool
}

func (m *movingSigner) Sign(ctx context.Context, commitData, keyID string) (*client.SignResult, error) {
	if !m.done {
		m.done = true
		commit(m.t, m.dir, "concurrent", serviceEmail)
	}
	return m.Signer.Sign(ctx, commitData, keyID)
}

// A run makes one network round-trip per commit, so the branch has a long
// window to move underneath it. Without the compare-and-swap that commit would
// be discarded without a word.
func TestRunRefusesWhenHeadMovedDuringTheRun(t *testing.T) {
	dir, svc := serviceFixture(t)
	base := head(t, dir)
	commit(t, dir, "mine", serviceEmail)

	signer := &movingSigner{Signer: svc.api, t: t, dir: dir}
	result, err := Run(t.Context(), signer, Options{Dir: dir, Base: base, DefaultBranch: "master"})
	if err == nil {
		t.Fatal("expected the run to refuse to move a branch that changed underneath it")
	}
	if !strings.Contains(err.Error(), "HEAD moved") {
		t.Errorf("expected the error to name the cause, got: %v", err)
	}
	if result != nil && result.RefUpdated {
		t.Error("the run must not report a ref update it did not make")
	}
	if got := head(t, dir); got == base {
		t.Error("expected the concurrent commit to survive")
	}
}

// A run must operate on the directory it was given, not on whatever repository
// the ambient environment names. GIT_DIR is set inside every git hook, under
// "git rebase --exec" and under "git bisect run", and git reads it before it
// looks at the working directory — so without scrubbing it, --repo would
// rewrite history in the caller's repository instead.
func TestRunIgnoresAmbientGitDir(t *testing.T) {
	dir, svc := serviceFixture(t)
	base := head(t, dir)
	commit(t, dir, "first", serviceEmail)

	bystander := initRepo(t)
	commit(t, bystander, "untouched", serviceEmail)
	before := head(t, bystander)

	t.Setenv("GIT_DIR", filepath.Join(bystander, ".git"))

	result, _, err := runEngine(t, dir, svc.api, Options{Base: base})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.RefUpdated || result.Tip == result.Head {
		t.Fatalf("expected the target repository to be rewritten, got %+v", result)
	}
	if after := head(t, bystander); after != before {
		t.Errorf("the run moved HEAD in the repository GIT_DIR named: %s -> %s", before, after)
	}
	// GIT_DIR is relative to the process working directory, so this reads the
	// target repository even with the ambient value still set.
	if got := git(t, dir, []string{"GIT_DIR=.git"}, "rev-parse", "HEAD"); got != result.Tip {
		t.Errorf("expected HEAD at %s in the target repository, got %s", result.Tip, got)
	}
}

func TestWithoutRepoEnvKeepsEverythingElse(t *testing.T) {
	got := withoutRepoEnv([]string{
		"GIT_DIR=/elsewhere/.git",
		"GIT_WORK_TREE=/elsewhere",
		"GIT_AUTHOR_NAME=Kept",
		"PATH=/usr/bin",
		"MALFORMED",
	})

	want := []string{"GIT_AUTHOR_NAME=Kept", "PATH=/usr/bin", "MALFORMED"}
	if !slices.Equal(got, want) {
		t.Errorf("expected %v, got %v", want, got)
	}
}
