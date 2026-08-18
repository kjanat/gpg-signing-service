package gitsign

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const (
	gpgProgram  = "gpg"
	interopUID  = "Interop Key <interop@example.test>"
	interopMail = "interop@example.test"
)

// The rest of the package no longer touches gpg: commits are parsed with
// go-git and signatures checked with go-crypto. That removes a runtime
// dependency, and with it the free cross-implementation check the old suite
// got by driving gpg for every fixture.
//
// These two tests put that check back where it matters, in both directions:
// gpg must accept what this package writes, and this package must accept what
// gpg wrote. They skip when the binary is absent, so they cost nothing on a
// machine that never installed it.

// requireGPG skips a test that needs the real gpg binary.
func requireGPG(t *testing.T) string {
	t.Helper()
	requireGit(t)
	if _, err := exec.LookPath(gpgProgram); err != nil {
		t.Skipf("%s is not on PATH; skipping the interoperability test", gpgProgram)
	}

	home := t.TempDir()
	// gpg refuses to use a homedir other users can read.
	// #nosec G302 -- this is a directory, which needs the execute bit to be usable.
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatalf("could not secure the test keyring: %v", err)
	}
	// Registered after t.TempDir's own cleanup, so it runs first and the
	// agent's sockets are gone before the directory is removed.
	t.Cleanup(func() {
		// #nosec G204 -- test fixture; the only variable is a t.TempDir path.
		_ = exec.Command("gpgconf", "--homedir", home, "--kill", "all").Run()
	})
	return home
}

// gpgRun drives gpg against a throwaway keyring and returns its stdout.
func gpgRun(t *testing.T, home string, stdin []byte, args ...string) []byte {
	t.Helper()

	full := append([]string{
		"--homedir", home, "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
	}, args...)
	// #nosec G204 -- test fixture; every argument is a literal from this file.
	cmd := exec.Command(gpgProgram, full...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("gpg %s failed: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return stdout.Bytes()
}

// gpg's signature must satisfy this package's verifier, or a commit signed by
// anything other than this tool reads as unverified and gets rewritten.
func TestVerifyAcceptsACommitTheGPGBinarySigned(t *testing.T) {
	home := requireGPG(t)
	gpgRun(t, home, nil, "--quick-generate-key", interopUID, "ed25519", "sign", "never")
	armored := string(gpgRun(t, home, nil, "--armor", "--export", interopMail))

	dir := initRepo(t)
	env := append(identity(interopMail), "GNUPGHOME="+home)
	git(t, dir, env, "-c", "gpg.program=gpg", "-c", "gpg.format=openpgp",
		"-c", "user.signingkey="+interopMail, "commit", "-S", "--allow-empty", "-m", "signed by gpg")

	key, err := newSigningKey(armored)
	if err != nil {
		t.Fatalf("could not read the exported key: %v", err)
	}
	if good, detail := key.verify(gitRaw(t, dir, nil, "cat-file", "commit", head(t, dir))); !good {
		t.Errorf("gpg's own signature did not verify in-process: %s", detail)
	}
}

// The reverse, and the one an operator actually feels: git log --show-signature
// has to be happy with the objects a run writes. Nothing else in the suite
// checks this now that verification no longer goes through git.
func TestGitVerifiesTheCommitsARunWrites(t *testing.T) {
	home := requireGPG(t)
	dir, svc := serviceFixture(t)
	base := head(t, dir)
	commit(t, dir, "first", serviceEmail)

	result, out, err := runEngine(t, dir, svc.api, Options{Base: base})
	if err != nil {
		t.Fatalf("unexpected error: %v\n%s", err, out)
	}

	gpgRun(t, home, []byte(exportKey(t, svc.entity)), "--quiet", "--import")
	// gpg.minTrustLevel is pinned because a keyring built by importing the key
	// carries no ownertrust, and anything above the default would reject an
	// otherwise good signature.
	// #nosec G204 -- test fixture; the only variable is a SHA this run wrote.
	verify := exec.Command(gitProgram, "-c", "gpg.program=gpg", "-c", "gpg.format=openpgp",
		"-c", "gpg.minTrustLevel=undefined", "verify-commit", "--raw", result.Tip)
	verify.Dir = dir
	verify.Env = append(os.Environ(), "GNUPGHOME="+home)
	var stderr bytes.Buffer
	verify.Stderr = &stderr
	if err := verify.Run(); err != nil {
		t.Fatalf("git verify-commit rejected the rewritten tip: %v\n%s", err, stderr.String())
	}
	if !bytes.Contains(stderr.Bytes(), []byte("[GNUPG:] GOODSIG")) {
		t.Errorf("expected a good signature from git, got:\n%s", stderr.String())
	}
}
