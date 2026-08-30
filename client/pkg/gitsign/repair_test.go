package gitsign

import (
	"bytes"
	"strings"
	"testing"
)

// The failure this whole command exists for. A commit the squash-merge path
// manufactured claims a bot as author and GitHub as committer; a repair has to
// leave it claiming the person whose key signs it, and change nothing else.
func TestRepairRewritesBotProvenanceAsTheTargetIdentity(t *testing.T) {
	f := newRepairFixture(t)
	before := map[string]repairSnapshot{}
	for _, sha := range f.chain {
		before[sha] = snapshot(t, f, sha)
	}

	result, _, err := f.repair(t, nil)
	if err != nil {
		t.Fatalf("repair failed: %v", err)
	}
	if result.Repaired != len(f.chain) {
		t.Fatalf("repaired %d commit(s), want %d", result.Repaired, len(f.chain))
	}
	if result.Tip == "" || result.Tip == f.tip {
		t.Fatalf("the repaired tip is %q, which is not a rewrite of %s", result.Tip, f.tip)
	}

	mapped := mapping(t, result, f.chain)
	previous := f.base
	for _, old := range f.chain {
		fresh := mapped[old]
		after := snapshot(t, f, fresh)
		was := before[old]

		if after.author != ownerIdentity {
			t.Errorf("%s: author is %q, want %q", short(old), after.author, ownerIdentity)
		}
		if after.committer != ownerIdentity {
			t.Errorf("%s: committer is %q, want %q", short(old), after.committer, ownerIdentity)
		}
		if was.author == ownerIdentity || was.committer == ownerIdentity {
			t.Fatalf("%s: the fixture was not broken to begin with", short(old))
		}

		if after.authorWhen != was.authorWhen {
			t.Errorf("%s: author time is %q, want the original %q", short(old), after.authorWhen, was.authorWhen)
		}
		if after.committerWhen != was.committerWhen {
			t.Errorf("%s: committer time is %q, want the original %q", short(old), after.committerWhen, was.committerWhen)
		}
		if after.tree != was.tree {
			t.Errorf("%s: tree is %s, want the original %s", short(old), after.tree, was.tree)
		}
		if !bytes.Equal(after.message, was.message) {
			t.Errorf("%s: message bytes changed:\n got %q\nwant %q", short(old), after.message, was.message)
		}
		if len(after.parents) != 1 || after.parents[0] != previous {
			t.Errorf("%s: parents are %v, want [%s]", short(old), after.parents, previous)
		}

		assertVerifies(t, f.dir, &fixture{entity: f.entity}, fresh)
		previous = fresh
	}

	// The whole point of preserving trees per commit: the branch's content is
	// untouched by a rewrite of who wrote it.
	if got := git(t, f.dir, nil, "rev-parse", result.Tip+"^{tree}"); got != git(t, f.dir, nil, "rev-parse", f.tip+"^{tree}") {
		t.Errorf("the repaired tip carries tree %s, want the pre-repair tip's tree", got)
	}
	if result.Tree != git(t, f.dir, nil, "rev-parse", f.tip+"^{tree}") {
		t.Errorf("result.Tree is %s, want the pre-repair tip's tree", result.Tree)
	}
}

// A signature the broken chain already carried has to be gone before the new
// payload is signed, not sitting alongside it. Two signature headers is a
// commit git refuses to report a single signer for.
func TestRepairStripsAnExistingSignatureBeforeSigning(t *testing.T) {
	f := newRepairFixture(t)

	// Re-sign the tip with a foreign key, the way the first failed repair left
	// the chain: signed, but by a key that does not speak for its committer.
	foreign := newEntity(t, foreignName, foreignEmail)
	raw := f.rawCommit(t, f.tip)
	parents, err := parentsOf(raw)
	if err != nil {
		t.Fatalf("could not read the fixture tip: %v", err)
	}
	payload, err := unsignedObject(raw, parents)
	if err != nil {
		t.Fatalf("could not rebuild the fixture tip: %v", err)
	}
	signed := withSignature(payload, []byte(strings.Trim(detachSign(t, foreign, payload), "\n")), repoFormat(t, f.dir))
	resigned := strings.TrimSpace(string(gitRaw(t, f.dir, signed, "hash-object", "-t", "commit", "-w", "--stdin")))
	git(t, f.dir, nil, "update-ref", "HEAD", resigned, f.tip)
	f.tip = resigned
	f.chain[len(f.chain)-1] = resigned

	if before := f.rawCommit(t, f.tip); !bytes.Contains(before, []byte(sha1SignatureHeader+" ")) {
		t.Fatal("the fixture tip is not signed, so this test proves nothing")
	}

	result, _, err := f.repair(t, nil)
	if err != nil {
		t.Fatalf("repair failed: %v", err)
	}

	after := f.rawCommit(t, result.Tip)
	head, err := headerBlock(after)
	if err != nil {
		t.Fatalf("could not read the repaired tip: %v", err)
	}
	headers := 0
	for _, line := range bytes.Split(head, []byte("\n")) {
		if bytes.HasPrefix(line, []byte(sha1SignatureHeader+" ")) {
			headers++
		}
	}
	if headers != 1 {
		t.Errorf("the repaired tip carries %d %s headers, want exactly 1", headers, sha1SignatureHeader)
	}
	assertVerifies(t, f.dir, &fixture{entity: f.entity}, result.Tip)
}

// The expected tip is a lease, not a label. A branch that moved between the
// operator reading it and the run starting has to stop the run, because the
// repaired chain would otherwise be built from commits the force-with-lease is
// not replacing.
func TestRepairRefusesWhenHistoryMoved(t *testing.T) {
	f := newRepairFixture(t)
	stale := f.tip
	botCommit(t, f.dir, "four.txt", "four\n", "chore: concurrent", "2026-08-30T12:00:00+02:00", "2026-08-30T12:00:00+02:00")

	_, _, err := f.repair(t, func(o *RepairOptions) { o.ExpectedTip = stale })
	if err == nil {
		t.Fatal("expected a refusal: HEAD moved past the expected tip")
	}
	if !strings.Contains(err.Error(), "history moved") {
		t.Errorf("the refusal does not name the cause: %v", err)
	}
	if f.signer.calls != 0 {
		t.Errorf("the run made %d signing call(s) after the history check failed", f.signer.calls)
	}
}

// An identity the operator did not name is a commit this run has no mandate to
// reattribute. The refusal has to list them, because the remedy is to name them.
func TestRepairRefusesAnIdentityItWasNotToldToExpect(t *testing.T) {
	f := newRepairFixture(t)

	_, _, err := f.repair(t, func(o *RepairOptions) { o.ExpectIdentities = []string{botEmail} })
	if err == nil {
		t.Fatal("expected a refusal: the committer address was never named")
	}
	if !strings.Contains(err.Error(), githubEmail) {
		t.Errorf("the refusal does not name the unexpected identity: %v", err)
	}
	if f.signer.calls != 0 {
		t.Errorf("the run made %d signing call(s) before validating identities", f.signer.calls)
	}
}

// The dangerous flags have no defaults. Each one missing is its own refusal,
// and none of them reaches the signing service.
func TestRepairRefusesWithoutItsExplicitBounds(t *testing.T) {
	f := newRepairFixture(t)

	for name, mutate := range map[string]func(*RepairOptions){
		"base":            func(o *RepairOptions) { o.Base = "" },
		"expected tip":    func(o *RepairOptions) { o.ExpectedTip = "" },
		"identity":        func(o *RepairOptions) { o.Identity = "" },
		"expect identity": func(o *RepairOptions) { o.ExpectIdentities = nil },
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := f.repair(t, mutate); err == nil {
				t.Fatalf("expected a refusal with no %s", name)
			}
		})
	}
	if f.signer.calls != 0 {
		t.Errorf("the run made %d signing call(s) while validating its own options", f.signer.calls)
	}
}

// A plan has to cost nothing: no signature requested, no object written, and
// no tip a careless caller could push.
func TestRepairDryRunSignsNothingAndWritesNothing(t *testing.T) {
	f := newRepairFixture(t)
	before := objectCount(t, f)

	result, out, err := f.repair(t, func(o *RepairOptions) { o.DryRun = true })
	if err != nil {
		t.Fatalf("the dry run failed: %v", err)
	}
	if f.signer.calls != 0 {
		t.Errorf("the dry run made %d signing call(s)", f.signer.calls)
	}
	if result.Tip != "" {
		t.Errorf("the dry run reported tip %q; a plan must not hand back something to push", result.Tip)
	}
	if result.Repaired != 0 {
		t.Errorf("the dry run reported %d repaired commit(s)", result.Repaired)
	}
	if got := objectCount(t, f); got != before {
		t.Errorf("the dry run wrote %d object(s)", got-before)
	}
	if !strings.Contains(out, "Dry run") {
		t.Errorf("the dry run does not say so in its output:\n%s", out)
	}

	// It still reports what it would do, which is the only reason to run it.
	if len(result.Mapping) != len(f.chain) {
		t.Fatalf("the plan covers %d commit(s), want %d", len(result.Mapping), len(f.chain))
	}
	for _, entry := range result.Mapping {
		if entry.NewCommit != "" {
			t.Errorf("%s: the plan claims a new SHA %s", short(entry.Commit), entry.NewCommit)
		}
		if !strings.Contains(entry.Author, botEmail) {
			t.Errorf("%s: the plan does not record the identity being replaced (%q)", short(entry.Commit), entry.Author)
		}
	}
}

// A service that signs the right bytes with the wrong key produces commits git
// reports as Unverified, which is exactly the state the repair is undoing. The
// run must not hand back a tip built out of them.
func TestRepairRefusesASignatureTheServiceKeyDoesNotVerify(t *testing.T) {
	f := newRepairFixture(t)
	impostor := newEntity(t, foreignName, foreignEmail)
	f.signer.sign = func(payload []byte) (string, error) { return signPayload(impostor, payload) }

	result, _, err := f.repair(t, nil)
	if err == nil {
		t.Fatal("expected a refusal: the signature was made by a key the service does not publish")
	}
	if !strings.Contains(err.Error(), "does not verify") {
		t.Errorf("the refusal does not name the cause: %v", err)
	}
	if result != nil && result.Tip != "" {
		t.Errorf("a failed repair reported tip %q", result.Tip)
	}
	if git(t, f.dir, nil, "rev-parse", "HEAD") != f.tip {
		t.Error("the failed repair moved HEAD")
	}
}

// The service signing something other than what it was handed is the same
// class of failure one step earlier, and the read-back check is what catches it.
func TestRepairRefusesASignatureOverDifferentBytes(t *testing.T) {
	f := newRepairFixture(t)
	entity := f.entity
	f.signer.sign = func(payload []byte) (string, error) {
		return signPayload(entity, append(payload, '!'))
	}

	if _, _, err := f.repair(t, nil); err == nil {
		t.Fatal("expected a refusal: the signature covers bytes the commit does not hold")
	}
}

// Nothing this command does is allowed to touch a ref. The workflow performs
// one force-with-lease of its own after checking the tip, and a command that
// moved HEAD would make that lease meaningless.
func TestRepairMovesNoRefAndPushesNothing(t *testing.T) {
	f := newRepairFixture(t)

	result, out, err := f.repair(t, nil)
	if err != nil {
		t.Fatalf("repair failed: %v", err)
	}
	if got := git(t, f.dir, nil, "rev-parse", "HEAD"); got != f.tip {
		t.Errorf("HEAD is at %s, want the untouched %s", got, f.tip)
	}
	if result.RefUpdated || result.Pushed {
		t.Errorf("the result claims refUpdated=%v pushed=%v", result.RefUpdated, result.Pushed)
	}
	if !strings.Contains(out, "force-with-lease") {
		t.Errorf("the run does not tell the operator how to publish the tip:\n%s", out)
	}
}

// A range whose base is not below the tip is an operator error with a specific
// remedy, and the run must not start guessing at one.
func TestRepairRefusesAnEmptyRange(t *testing.T) {
	f := newRepairFixture(t)

	_, _, err := f.repair(t, func(o *RepairOptions) { o.Base = f.tip })
	if err == nil {
		t.Fatal("expected a refusal: base is the tip, so the range is empty")
	}
	if !strings.Contains(err.Error(), "exclusive lower bound") {
		t.Errorf("the refusal does not explain what base means: %v", err)
	}
}

func TestRepairRefusesABaseTheTipDoesNotReach(t *testing.T) {
	f := newRepairFixture(t)

	// A commit off to one side of the fixture's chain, the shape a mistyped ref
	// resolves to: a branch that forked earlier and went somewhere else.
	sidetrack := git(t, f.dir, nil, "commit-tree", f.base+"^{tree}", "-p", f.base, "-m", "chore: sidetrack")

	// Nothing about the walk itself would notice. rev-list sidetrack..tip is not
	// empty — it silently starts at their merge base — so the range would come
	// back wider than the one the caller described.
	if reached := git(t, f.dir, nil, "rev-list", "--count", sidetrack+".."+f.tip); reached == "0" {
		t.Fatalf("the fixture is wrong: %s..%s is empty, so the range check would catch this on its own",
			short(sidetrack), short(f.tip))
	}

	_, _, err := f.repair(t, func(o *RepairOptions) { o.Base = sidetrack })
	if err == nil {
		t.Fatal("expected a refusal: base is not an ancestor of the tip")
	}
	if !strings.Contains(err.Error(), "is not an ancestor of") {
		t.Errorf("the refusal does not say the base is off the tip's history: %v", err)
	}
	if f.signer.calls != 0 {
		t.Errorf("the refusal came after %d signing call(s); it must come before any", f.signer.calls)
	}
}

// repairSnapshot is everything about a commit the repair promises to keep,
// alongside the identity it promises to change.
type repairSnapshot struct {
	author        string
	authorWhen    string
	committer     string
	committerWhen string
	tree          string
	message       []byte
	parents       []string
}

// snapshot reads those facts straight out of the object store.
func snapshot(t *testing.T, f *repairFixture, sha string) repairSnapshot {
	t.Helper()

	raw := f.rawCommit(t, sha)
	author, committer, err := readIdents(raw)
	if err != nil {
		t.Fatalf("%s: could not read the identity headers: %v", short(sha), err)
	}
	tree, err := treeHeader(raw)
	if err != nil {
		t.Fatalf("%s: could not read the tree header: %v", short(sha), err)
	}
	message, err := messageBody(raw)
	if err != nil {
		t.Fatalf("%s: could not read the message: %v", short(sha), err)
	}
	parents, err := parentsOf(raw)
	if err != nil {
		t.Fatalf("%s: could not read the parents: %v", short(sha), err)
	}
	return repairSnapshot{
		author: author.display(), authorWhen: author.when,
		committer: committer.display(), committerWhen: committer.when,
		tree: tree, message: message, parents: parents,
	}
}

// mapping turns the result's old -> new records into a lookup, checking that
// it covers the range in order and nothing else.
func mapping(t *testing.T, result *RepairResult, commits []string) map[string]string {
	t.Helper()

	if len(result.Mapping) != len(commits) {
		t.Fatalf("the mapping covers %d commit(s), want %d", len(result.Mapping), len(commits))
	}
	out := make(map[string]string, len(commits))
	for index, entry := range result.Mapping {
		if entry.Commit != commits[index] {
			t.Fatalf("mapping entry %d is %s, want %s: the mapping is not in oldest-to-newest order",
				index, short(entry.Commit), short(commits[index]))
		}
		if entry.NewCommit == "" {
			t.Fatalf("mapping entry %d has no new SHA", index)
		}
		out[entry.Commit] = entry.NewCommit
	}
	return out
}

// objectCount is how many loose and packed objects the fixture holds, for the
// dry run that must add none.
func objectCount(t *testing.T, f *repairFixture) int {
	t.Helper()
	return len(strings.Fields(git(t, f.dir, nil, "cat-file", "--batch-all-objects", "--batch-check=%(objectname)")))
}

// A merge carries several parents and only some of them may be inside the
// repaired range, so each one is remapped independently. A repair that
// remapped only the first parent would silently drop the merged side.
func TestRepairRemapsEveryParentOfAMerge(t *testing.T) {
	f := newRepairFixture(t)

	// A side branch off the base, merged back into the chain. Its commit is in
	// the range too, so both of the merge's parents move.
	git(t, f.dir, nil, "checkout", "--quiet", "-b", "side", f.base)
	side := botCommit(t, f.dir, "side.txt", "side\n", "feat: side", "2026-08-30T08:00:00+02:00", "2026-08-30T08:01:00+02:00")
	git(t, f.dir, nil, "checkout", "--quiet", "master")
	git(t, f.dir, authored(botName, botEmail, githubName, githubEmail,
		"2026-08-30T13:00:00+02:00", "2026-08-30T13:01:00+02:00"),
		"merge", "--no-ff", "--no-edit", "-m", "merge: side", side)

	f.tip = head(t, f.dir)
	f.chain = strings.Fields(git(t, f.dir, nil, "rev-list", "--reverse", "--topo-order", f.base+".."+f.tip))

	result, _, err := f.repair(t, nil)
	if err != nil {
		t.Fatalf("repair failed: %v", err)
	}

	mapped := mapping(t, result, f.chain)
	merge := snapshot(t, f, result.Tip)
	was := snapshot(t, f, f.tip)
	if len(was.parents) != 2 {
		t.Fatalf("the fixture tip has %d parent(s), want a merge", len(was.parents))
	}
	if len(merge.parents) != 2 {
		t.Fatalf("the repaired tip has %d parent(s), want 2", len(merge.parents))
	}
	for index, parent := range was.parents {
		if merge.parents[index] != mapped[parent] {
			t.Errorf("parent %d is %s, want the rewritten %s", index, merge.parents[index], mapped[parent])
		}
	}
	if merge.tree != was.tree {
		t.Errorf("the repaired merge points at tree %s, want %s", merge.tree, was.tree)
	}
	assertVerifies(t, f.dir, &fixture{entity: f.entity}, result.Tip)
}
