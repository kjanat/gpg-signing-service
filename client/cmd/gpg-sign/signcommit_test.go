package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

const (
	testSignCommitUID   = "CLI Service Key <cli-service@example.test>"
	testSignCommitEmail = "cli-service@example.test"
)

// signCommitArgs builds the flag set the command reads, so tests can call RunE
// directly instead of parsing a command line.
type signCommitArgs struct {
	keyID         string
	base          string
	defaultBranch string
	repo          string
	allowResign   bool
	signOthers    bool
	scanLimit     int
}

func (a signCommitArgs) command() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().String("key-id", a.keyID, "")
	cmd.Flags().String("base", a.base, "")
	cmd.Flags().String("default-branch", cmp.Or(a.defaultBranch, "master"), "")
	cmd.Flags().Bool("allow-resign", a.allowResign, "")
	cmd.Flags().Bool("sign-others", a.signOthers, "")
	cmd.Flags().Int("scan-limit", a.scanLimit, "")
	cmd.Flags().String("repo", a.repo, "")
	return cmd
}

func TestSignCommitCommandIsRegistered(t *testing.T) {
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "sign-commit" {
			return
		}
	}
	t.Error("sign-commit is not registered on the root command")
}

func TestSignCommitCommandValidation(t *testing.T) {
	tests := []struct {
		name        string
		args        signCommitArgs
		expectedErr string
	}{
		{
			name:        "negative scan limit",
			args:        signCommitArgs{scanLimit: -1},
			expectedErr: "--scan-limit must not be negative",
		},
		{
			name:        "not a repository",
			args:        signCommitArgs{repo: t.TempDir()},
			expectedErr: "sign-commit failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := signCommitCmd.RunE(tt.args.command(), nil)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Errorf("expected an error containing %q, got %v", tt.expectedErr, err)
			}
		})
	}
}

func TestSignCommitCommand(t *testing.T) {
	dir, base := newSignCommitFixture(t)

	stdout := captureStdout(t, func() {
		if err := signCommitCmd.RunE(signCommitArgs{repo: dir, base: base}.command(), nil); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	if !strings.Contains(stdout, "signed ") {
		t.Errorf("expected a per-commit progress line, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Signed 1 of 1 commit(s)") {
		t.Errorf("expected a summary line, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "Nothing was pushed") {
		t.Errorf("expected the command to say it did not push, got:\n%s", stdout)
	}
}

func TestSignCommitCommandJSON(t *testing.T) {
	dir, base := newSignCommitFixture(t)

	previousJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = previousJSON }()

	stdout := captureStdout(t, func() {
		if err := signCommitCmd.RunE(signCommitArgs{repo: dir, base: base}.command(), nil); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	var result struct {
		Scanned    int    `json:"commitsScanned"`
		Signed     int    `json:"commitsSigned"`
		Tip        string `json:"tip"`
		RefUpdated bool   `json:"refUpdated"`
		Pushed     bool   `json:"pushed"`
	}
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("expected stdout to hold only JSON, got %q: %v", stdout, err)
	}
	if result.Scanned != 1 || result.Signed != 1 {
		t.Errorf("expected 1 of 1 signed, got %d of %d", result.Signed, result.Scanned)
	}
	if !result.RefUpdated || result.Tip == "" {
		t.Errorf("expected a moved ref and a tip, got %+v", result)
	}
	if result.Pushed {
		t.Error("the command must never report a push")
	}
}

// captureStdout runs fn with os.Stdout replaced by a pipe and returns what it
// wrote.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("could not create a pipe: %v", err)
	}
	previous := os.Stdout
	os.Stdout = writer

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, reader)
		done <- buf.String()
	}()

	fn()

	os.Stdout = previous
	_ = writer.Close()
	output := <-done
	_ = reader.Close()
	return output
}

// newSignCommitFixture builds a repository with one signable commit and points
// the global client flags at a service that signs with a local key. It returns
// the repository and the base of the range.
func newSignCommitFixture(t *testing.T) (dir, base string) {
	t.Helper()

	for _, tool := range []string{"git", "gpg"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not on PATH; skipping the git-dependent test", tool)
		}
	}

	home := t.TempDir()
	// #nosec G302 -- this is a directory, which needs the execute bit to be usable.
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatalf("could not secure the test keyring: %v", err)
	}
	t.Cleanup(func() {
		// #nosec G204 -- test fixture; the only variable is a t.TempDir path.
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run()
	})
	gpgRun(t, home, nil, "--quick-generate-key", testSignCommitUID, "ed25519", "sign", "never")

	armored := gpgRun(t, home, nil, "--armor", "--export", testSignCommitEmail)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/public-key" {
			_, _ = fmt.Fprint(w, armored)
			return
		}
		var payload bytes.Buffer
		_, _ = payload.ReadFrom(r.Body)
		signature, err := gpgOutput(home, payload.Bytes(),
			"--armor", "--detach-sign", "--local-user", testSignCommitEmail)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprint(w, signature)
	}))
	t.Cleanup(server.Close)

	previousURL, previousTimeout := apiURL, timeout
	apiURL, timeout = server.URL, 30*time.Second
	t.Cleanup(func() { apiURL, timeout = previousURL, previousTimeout })

	dir = t.TempDir()
	env := []string{
		envAuthorName + "=" + fixtureName, envAuthorEmail + "=" + testSignCommitEmail,
		envCommitterName + "=" + fixtureName, envCommitterEmail + "=" + testSignCommitEmail,
	}
	gitRun(t, dir, env, "init", "--initial-branch=master")
	gitRun(t, dir, env, "config", "commit.gpgsign", "false")
	gitRun(t, dir, env, "commit", "--allow-empty", "-m", "root")
	base = strings.TrimSpace(gitRun(t, dir, env, "rev-parse", "HEAD"))
	gitRun(t, dir, env, "commit", "--allow-empty", "-m", "signable")
	return dir, base
}

// gpgOutput drives gpg and returns an error rather than failing the test, so
// the httptest handler can call it: a testing.T failure helper invoked outside
// the test goroutine panics the process instead of failing the test.
func gpgOutput(home string, stdin []byte, args ...string) (string, error) {
	full := append([]string{"--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", ""}, args...)
	var stdout, stderr bytes.Buffer
	// #nosec G204 -- test fixture; every argument is a literal from this file.
	cmd := exec.Command("gpg", full...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("gpg %s failed: %w\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String(), nil
}

func gpgRun(t *testing.T, home string, stdin []byte, args ...string) string {
	t.Helper()

	out, err := gpgOutput(home, stdin, args...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// hermeticGit is the environment every git command in this suite runs under.
//
// The developer's global and system config must not decide what the fixtures
// look like, and a git command that writes an object otherwise guesses an
// identity from the host's username and hostname — a guess that works on a
// workstation and fails on a clean CI runner with "Author identity unknown".
// Naming both here means no fixture depends on the host having either.
//
// Caller entries are appended after these and win, since for a duplicate
// environment key the last occurrence is the one that takes effect.
func hermeticGit() []string {
	return []string{
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_CONFIG_SYSTEM=" + os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
		envAuthorName + "=" + fixtureName, envAuthorEmail + "=" + testSignCommitEmail,
		envCommitterName + "=" + fixtureName, envCommitterEmail + "=" + testSignCommitEmail,
	}
}

// gitEnv is the full environment for a fixture git command. Every ambient
// GIT_* variable is dropped rather than shadowed: GIT_CONFIG_COUNT and its
// GIT_CONFIG_KEY_n companions inject config outranking every file, so a host
// that sets them could otherwise still reach into a fixture.
func gitEnv(env []string) []string {
	environ := os.Environ()
	kept := make([]string, 0, len(environ))
	for _, entry := range environ {
		if strings.HasPrefix(entry, "GIT_") {
			continue
		}
		kept = append(kept, entry)
	}
	return append(append(kept, hermeticGit()...), env...)
}

func gitRun(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()

	var stdout, stderr bytes.Buffer
	// #nosec G204 -- test fixture; every argument is a literal from this file.
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv(env)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}

// A failed run in --json mode still has to emit a document. A ResignError is
// the sharpest case: it carries a per-commit report built to be consumed, and
// the progress text on stderr is not a contract.
func TestSignCommitCommandJSONOnRefusal(t *testing.T) {
	dir, root := newSignCommitFixture(t)

	env := []string{
		envAuthorName + "=" + fixtureName, envAuthorEmail + "=" + testSignCommitEmail,
		envCommitterName + "=" + fixtureName, envCommitterEmail + "=" + testSignCommitEmail,
	}
	first := strings.TrimSpace(gitRun(t, dir, env, "rev-parse", "HEAD"))
	gitRun(t, dir, env, "commit", "--allow-empty", "-m", "second")

	// Sign only the top commit, so the one below it is still unsigned. The next
	// run has to rewrite that one, which invalidates the signature above it.
	if err := signCommitCmd.RunE(signCommitArgs{repo: dir, base: first}.command(), nil); err != nil {
		t.Fatalf("could not prepare a signed commit: %v", err)
	}

	previousJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = previousJSON }()

	var runErr error
	stdout := captureStdout(t, func() {
		runErr = signCommitCmd.RunE(signCommitArgs{repo: dir, base: root}.command(), nil)
	})
	if runErr == nil {
		t.Fatal("expected the run to refuse to rewrite an already-signed commit")
	}

	var document struct {
		Error  string `json:"error"`
		Resign *struct {
			Stale   int      `json:"stale"`
			Commits []string `json:"commits"`
			Report  []string `json:"report"`
		} `json:"resign"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("expected stdout to hold only JSON, got %q: %v", stdout, err)
	}
	if document.Error == "" {
		t.Error("expected the document to carry the error")
	}
	if document.Resign == nil {
		t.Fatalf("expected the refusal detail, got %q", stdout)
	}
	if len(document.Resign.Commits) != 1 || len(document.Resign.Report) != 1 {
		t.Errorf("expected one blocked commit and one report line, got %+v", document.Resign)
	}
	if document.Resign.Stale != 2 {
		t.Errorf("expected both commits counted as stale, got %d", document.Resign.Stale)
	}
}

// Any other failure has to produce a document too, even when the run never got
// far enough to build a result.
func TestSignCommitCommandJSONOnEarlyFailure(t *testing.T) {
	previousJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = previousJSON }()

	var runErr error
	stdout := captureStdout(t, func() {
		runErr = signCommitCmd.RunE(signCommitArgs{repo: t.TempDir()}.command(), nil)
	})
	if runErr == nil {
		t.Fatal("expected a failure outside a repository")
	}

	var document struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &document); err != nil {
		t.Fatalf("expected stdout to hold only JSON, got %q: %v", stdout, err)
	}
	if !strings.Contains(document.Error, "sign-commit failed") {
		t.Errorf("expected the wrapped error, got %q", document.Error)
	}
}
