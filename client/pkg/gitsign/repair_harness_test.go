package gitsign

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/kjanat/gpg-signing-service/client/pkg/client"
)

// The provenance failure this command exists for, as the REST squash-merge
// path wrote it: a bot named as author, GitHub named as committer, and neither
// one the person who wrote the code.
const (
	botName       = "claude[bot]"
	botEmail      = "209825114+claude[bot]@users.noreply.github.com"
	githubName    = "GitHub"
	githubEmail   = "noreply@github.com"
	ownerName     = "Kaj Kowalski"
	ownerEmail    = "info@kajkowalski.nl"
	ownerIdentity = ownerName + " <" + ownerEmail + ">"
)

// stubSigner is a Signer whose signing half the test controls, for the paths
// where the service has to misbehave: sign the wrong bytes, sign with the
// wrong key, or never be called at all.
type stubSigner struct {
	armored string
	sign    func(payload []byte) (string, error)
	calls   int
}

func (s *stubSigner) PublicKey(context.Context, string) (string, error) { return s.armored, nil }

func (s *stubSigner) Sign(_ context.Context, data, _ string) (*client.SignResult, error) {
	s.calls++
	signature, err := s.sign([]byte(data))
	if err != nil {
		return nil, err
	}
	return &client.SignResult{Signature: signature}, nil
}

// honestSigner signs exactly the payload it is handed with the service key,
// which is what the real service does.
func honestSigner(t *testing.T, entity *openpgp.Entity) *stubSigner {
	t.Helper()
	return &stubSigner{
		armored: exportKey(t, entity),
		sign:    func(payload []byte) (string, error) { return signPayload(entity, payload) },
	}
}

// authored is the environment that pins an author and a committer separately,
// with their own timestamps and offsets. The two differ on purpose: the repair
// has to keep each header's own time, and a fixture where they match would
// pass even if it kept only one.
func authored(authorName, authorEmail, committerName, committerEmail, authorDate, committerDate string) []string {
	return []string{
		"GIT_AUTHOR_NAME=" + authorName, "GIT_AUTHOR_EMAIL=" + authorEmail, "GIT_AUTHOR_DATE=" + authorDate,
		"GIT_COMMITTER_NAME=" + committerName, "GIT_COMMITTER_EMAIL=" + committerEmail,
		"GIT_COMMITTER_DATE=" + committerDate,
	}
}

// botCommit adds a commit shaped exactly like the ones the squash-merge path
// manufactured, carrying real file content so the tree is worth preserving.
func botCommit(t *testing.T, dir, name, content, message, authorDate, committerDate string) string {
	t.Helper()

	writeFile(t, dir, name, content)
	git(t, dir, nil, "add", name)
	git(t, dir, authored(botName, botEmail, githubName, githubEmail, authorDate, committerDate),
		"commit", "-m", message)
	return head(t, dir)
}

// writeFile puts a file in the fixture's working tree, for fixtures that need
// a tree worth preserving rather than an empty commit.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("could not write the fixture file %s: %v", name, err)
	}
}

// repairFixture is a repository holding a base commit plus a chain of
// bot-authored commits, and a service that signs with a key it also publishes.
type repairFixture struct {
	dir    string
	entity *openpgp.Entity
	signer *stubSigner
	base   string
	tip    string
	chain  []string
}

// newRepairFixture builds the standard three-commit broken chain.
func newRepairFixture(t *testing.T) *repairFixture {
	t.Helper()
	requireGit(t)

	dir := initRepo(t)
	entity := newEntity(t, serviceName, serviceEmail)
	base := head(t, dir)

	first := botCommit(t, dir, "one.txt", "one\n", "feat: first", "2026-08-30T09:15:00+02:00", "2026-08-30T09:16:00+00:00")
	second := botCommit(t, dir, "two.txt", "two\n", "fix: second\n\nWith a body.\n", "2026-08-29T23:59:59-05:00", "2026-08-30T10:00:00+02:00")
	third := botCommit(t, dir, "three.txt", "three\n", "docs: third", "2026-08-30T11:30:00+09:00", "2026-08-30T11:31:00+09:00")

	return &repairFixture{
		dir: dir, entity: entity, signer: honestSigner(t, entity),
		base: base, tip: third, chain: []string{first, second, third},
	}
}

// repair runs the engine against the fixture with the standard bounds.
func (f *repairFixture) repair(t *testing.T, mutate func(*RepairOptions)) (*RepairResult, string, error) {
	t.Helper()

	var out strings.Builder
	opts := RepairOptions{
		Dir:              f.dir,
		Base:             f.base,
		ExpectedTip:      f.tip,
		Identity:         ownerIdentity,
		ExpectIdentities: []string{botEmail, githubEmail},
		Out:              &out,
	}
	if mutate != nil {
		mutate(&opts)
	}
	result, err := Repair(t.Context(), f.signer, opts)
	t.Log(out.String())
	return result, out.String(), err
}

// rawCommit reads a commit object out of the fixture.
func (f *repairFixture) rawCommit(t *testing.T, sha string) []byte {
	t.Helper()
	return gitRaw(t, f.dir, nil, "cat-file", "commit", sha)
}
