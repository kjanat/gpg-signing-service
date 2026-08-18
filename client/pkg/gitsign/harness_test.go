package gitsign

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/kjanat/gpg-signing-service/client/pkg/client"
)

const (
	serviceName  = "Service Key"
	serviceEmail = "service@example.test"
	foreignName  = "Someone Else"
	foreignEmail = "someone@example.test"
)

// requireGit skips tests that need a real git binary, so the suite still runs
// on a machine that has none. Nothing here needs gpg: keys are generated,
// signed with, and verified in-process.
func requireGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath(gitProgram); err != nil {
		t.Skipf("%s is not on PATH; skipping the git-dependent test", gitProgram)
	}
}

// newEntity generates a throwaway ed25519 signing key.
func newEntity(t *testing.T, name, email string) *openpgp.Entity {
	t.Helper()

	entity, err := openpgp.NewEntity(name, "", email, &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA})
	if err != nil {
		t.Fatalf("could not generate a test key: %v", err)
	}
	return entity
}

// exportKey returns the armored public key, the shape the service hands back.
func exportKey(t *testing.T, entity *openpgp.Entity) string {
	t.Helper()

	var buf bytes.Buffer
	block, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("could not armor the test key: %v", err)
	}
	if err := entity.Serialize(block); err != nil {
		t.Fatalf("could not serialize the test key: %v", err)
	}
	if err := block.Close(); err != nil {
		t.Fatalf("could not close the armor block: %v", err)
	}
	return buf.String()
}

// detachSign produces the armored detached signature the fake service returns.
func detachSign(t *testing.T, entity *openpgp.Entity, payload []byte) string {
	t.Helper()

	var buf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&buf, entity, bytes.NewReader(payload), nil); err != nil {
		t.Fatalf("could not sign the test payload: %v", err)
	}
	return buf.String()
}

// newService stands up a signing service backed by a local key.
func newService(t *testing.T, entity *openpgp.Entity) *client.Client {
	t.Helper()

	armored := exportKey(t, entity)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/public-key" {
			_, _ = fmt.Fprint(w, armored)
			return
		}
		payload, err := readAll(r)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprint(w, detachSign(t, entity, payload))
	}))
	t.Cleanup(server.Close)

	c, err := client.New(server.URL)
	if err != nil {
		t.Fatalf("could not build a client: %v", err)
	}
	return c
}

func readAll(r *http.Request) ([]byte, error) {
	defer func() { _ = r.Body.Close() }()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r.Body)
	return buf.Bytes(), err
}

// git runs a git command in the test repository.
func git(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()

	var stdout, stderr bytes.Buffer
	// #nosec G204 -- test fixture; the arguments come from this file's helpers.
	cmd := exec.Command(gitProgram, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(stdout.String())
}

// gitRaw runs a git command and returns its stdout untrimmed, for the object
// bytes where a trailing newline is part of the content.
func gitRaw(t *testing.T, dir string, stdin []byte, args ...string) []byte {
	t.Helper()

	var stdout, stderr bytes.Buffer
	// #nosec G204 -- test fixture; the arguments come from this file's helpers.
	cmd := exec.Command(gitProgram, args...)
	cmd.Dir = dir
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.Bytes()
}

// initRepo creates an empty repository on master with one root commit.
func initRepo(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	git(t, dir, nil, "init", "--initial-branch=master")
	// Ambient config must not decide whether the fixtures are signed.
	git(t, dir, nil, "config", "commit.gpgsign", "false")
	commit(t, dir, "root", serviceEmail)
	return dir
}

// identity returns the environment that pins a commit's author and committer.
func identity(email string) []string {
	return []string{
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=" + email,
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=" + email,
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
	}
}

// commit adds an empty commit attributed to the given address.
func commit(t *testing.T, dir, message, email string) string {
	t.Helper()
	git(t, dir, identity(email), "commit", "--allow-empty", "-m", message)
	return git(t, dir, nil, "rev-parse", "HEAD")
}

// commitSignedBy adds an empty commit signed with a key the service does not
// hold, which is how a foreign signature gets into the fixtures.
//
// It writes the signed object the same way git does — sign the payload, embed
// it, rehash — because the alternative is asking a gpg binary the rest of this
// package no longer needs.
func commitSignedBy(t *testing.T, dir, message, email string, entity *openpgp.Entity) {
	t.Helper()

	sha := commit(t, dir, message, email)
	raw := gitRaw(t, dir, nil, "cat-file", "commit", sha)

	parents, err := parentsOf(raw)
	if err != nil {
		t.Fatalf("could not read the fixture commit: %v", err)
	}
	payload, err := unsignedObject(raw, parents)
	if err != nil {
		t.Fatalf("could not rebuild the fixture commit: %v", err)
	}

	signed := withSignature(payload, []byte(strings.Trim(detachSign(t, entity, payload), "\n")))
	newSHA := gitRaw(t, dir, signed, "hash-object", "-t", "commit", "-w", "--stdin")
	git(t, dir, nil, "update-ref", "HEAD", strings.TrimSpace(string(newSHA)), sha)
}

// runEngine drives the engine and captures its progress output.
func runEngine(t *testing.T, dir string, c *client.Client, opts Options) (*Result, string, error) {
	t.Helper()

	var out bytes.Buffer
	opts.Dir = dir
	opts.Out = &out
	if opts.DefaultBranch == "" {
		opts.DefaultBranch = "master"
	}
	result, err := Run(t.Context(), c, opts)
	t.Log(out.String())
	return result, out.String(), err
}

// marks flattens a result into "mark sha" pairs for assertions.
func marks(result *Result) []string {
	out := make([]string, 0, len(result.Rewrites))
	for _, rewrite := range result.Rewrites {
		out = append(out, string(rewrite.Mark)+" "+short(rewrite.Commit))
	}
	return out
}

// fixture pairs a signing service with the key it signs from.
type fixture struct {
	entity *openpgp.Entity
	api    *client.Client
}

// serviceFixture builds a repository plus a service that share one key.
func serviceFixture(t *testing.T) (string, *fixture) {
	t.Helper()
	requireGit(t)

	entity := newEntity(t, serviceName, serviceEmail)
	return initRepo(t), &fixture{entity: entity, api: newService(t, entity)}
}

// head returns the commit the test repository's HEAD points at.
func head(t *testing.T, dir string) string {
	t.Helper()
	return git(t, dir, nil, "rev-parse", "HEAD")
}

// assertVerifies checks the commit against the service's own key, the same way
// a reviewer would.
func assertVerifies(t *testing.T, dir string, f *fixture, sha string) {
	t.Helper()

	key, err := newSigningKey(exportKey(t, f.entity))
	if err != nil {
		t.Fatalf("could not read the service key: %v", err)
	}
	if good, detail := key.verify(gitRaw(t, dir, nil, "cat-file", "commit", sha)); !good {
		t.Errorf("%s does not verify against the service key: %s", short(sha), detail)
	}
}

// isRewrittenSHA reports whether the SHA is one the run produced.
func isRewrittenSHA(rewritten map[string]string, sha string) bool {
	for _, newSHA := range rewritten {
		if newSHA == sha {
			return true
		}
	}
	return false
}
