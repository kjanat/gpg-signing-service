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

	"github.com/kjanat/gpg-signing-service/client/pkg/client"
)

const (
	serviceUID   = "Service Key <service@example.test>"
	serviceEmail = "service@example.test"
	foreignUID   = "Someone Else <someone@example.test>"
	foreignEmail = "someone@example.test"
)

// requireTools skips tests that need real git and gpg binaries, so the suite
// still runs on a machine that has neither.
func requireTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{gitProgram, gpgProgram} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH; skipping the git-dependent test", tool)
		}
	}
}

// newGPGHome generates a throwaway signing key and returns its GNUPGHOME.
func newGPGHome(t *testing.T, uid string) string {
	t.Helper()

	home := t.TempDir()
	// #nosec G302 -- this is a directory, which needs the execute bit to be usable.
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatalf("could not secure the test keyring: %v", err)
	}
	// Registered after t.TempDir's own cleanup, so it runs first and the
	// agent's sockets are gone before the directory is removed.
	t.Cleanup(func() { killAgent(home) })

	out, err := gpgCommand(home, "--quick-generate-key", uid, "ed25519", "sign", "never").CombinedOutput()
	if err != nil {
		t.Fatalf("could not generate a test key: %v\n%s", err, out)
	}
	return home
}

// exportKey returns the armored public key of the given home.
func exportKey(t *testing.T, home, uid string) string {
	t.Helper()

	var stdout, stderr bytes.Buffer
	cmd := gpgCommand(home, "--armor", "--export", uid)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("could not export the test key: %v\n%s", err, stderr.String())
	}
	return stdout.String()
}

// detachSign produces the armored detached signature the fake service returns.
func detachSign(t *testing.T, home, uid string, payload []byte) string {
	t.Helper()

	var stdout, stderr bytes.Buffer
	cmd := gpgCommand(home, "--armor", "--detach-sign", "--local-user", uid)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("could not sign the test payload: %v\n%s", err, stderr.String())
	}
	return stdout.String()
}

// newService stands up a signing service backed by a local gpg key.
func newService(t *testing.T, home, uid string) *client.Client {
	t.Helper()

	armored := exportKey(t, home, uid)
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
		_, _ = fmt.Fprint(w, detachSign(t, home, uid, payload))
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

// gpgCommand builds a batch gpg invocation against a throwaway keyring.
func gpgCommand(home string, args ...string) *exec.Cmd {
	full := gpgArgs(home, "--pinentry-mode", "loopback", "--passphrase", "")
	// #nosec G204 -- test fixture; every argument is a literal from this file.
	return exec.Command(gpgProgram, append(full, args...)...)
}

// killAgent stops the gpg-agent a throwaway keyring started, so its sockets are
// gone before t.TempDir tries to remove the directory.
func killAgent(home string) {
	// #nosec G204 -- test fixture; the only variable is a t.TempDir path.
	_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run()
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
func commitSignedBy(t *testing.T, dir, message, email, home, uid string) {
	t.Helper()

	env := append(identity(email), "GNUPGHOME="+home)
	git(t, dir, env, "-c", "gpg.program=gpg", "-c", "gpg.format=openpgp",
		"-c", "user.signingkey="+uid, "commit", "-S", "--allow-empty", "-m", message)
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

// fixture pairs a signing service with the keyring it signs from.
type fixture struct {
	home string
	api  *client.Client
}

// serviceFixture builds a repository plus a service that share one key.
func serviceFixture(t *testing.T) (string, *fixture) {
	t.Helper()
	requireTools(t)

	home := newGPGHome(t, serviceUID)
	return initRepo(t), &fixture{home: home, api: newService(t, home, serviceUID)}
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

	verifyHome := t.TempDir()
	// #nosec G302 -- this is a directory, which needs the execute bit to be usable.
	if err := os.Chmod(verifyHome, 0o700); err != nil {
		t.Fatalf("could not secure the verification keyring: %v", err)
	}
	t.Cleanup(func() { killAgent(verifyHome) })

	importKey := gpgCommand(verifyHome, "--quiet", "--import")
	importKey.Stdin = strings.NewReader(exportKey(t, f.home, serviceUID))
	if out, err := importKey.CombinedOutput(); err != nil {
		t.Fatalf("could not import the service key: %v\n%s", err, out)
	}

	good, detail := (&repo{dir: dir}).verifyStatus(t.Context(), sha, verifyHome)
	if !good {
		t.Errorf("%s does not verify against the service key:\n%s", short(sha), detail)
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
