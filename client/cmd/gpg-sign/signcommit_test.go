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
			expectedErr: "--scan-limit must be a positive integer",
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
		_, _ = fmt.Fprint(w, gpgRun(t, home, payload.Bytes(),
			"--armor", "--detach-sign", "--local-user", testSignCommitEmail))
	}))
	t.Cleanup(server.Close)

	previousURL, previousTimeout := apiURL, timeout
	apiURL, timeout = server.URL, 30*time.Second
	t.Cleanup(func() { apiURL, timeout = previousURL, previousTimeout })

	dir = t.TempDir()
	env := []string{
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=" + testSignCommitEmail,
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=" + testSignCommitEmail,
	}
	gitRun(t, dir, env, "init", "--initial-branch=master")
	gitRun(t, dir, env, "config", "commit.gpgsign", "false")
	gitRun(t, dir, env, "commit", "--allow-empty", "-m", "root")
	base = strings.TrimSpace(gitRun(t, dir, env, "rev-parse", "HEAD"))
	gitRun(t, dir, env, "commit", "--allow-empty", "-m", "signable")
	return dir, base
}

func gpgRun(t *testing.T, home string, stdin []byte, args ...string) string {
	t.Helper()

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
		t.Fatalf("gpg %s failed: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}

func gitRun(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()

	var stdout, stderr bytes.Buffer
	// #nosec G204 -- test fixture; every argument is a literal from this file.
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.String()
}
