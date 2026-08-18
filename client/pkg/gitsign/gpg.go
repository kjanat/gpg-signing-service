package gitsign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// gpgStatusPrefix marks the machine-readable lines of gpg's --raw output.
const gpgStatusPrefix = "[GNUPG:] "

// gpgArgs builds the invocation prefix every gpg call shares: a pinned
// homedir, and no prompting, because nothing here has a terminal.
func gpgArgs(home string, args ...string) []string {
	return append([]string{"--homedir", home, "--batch"}, args...)
}

// gpgStatusReasons maps gpg status codes to an explanation, most specific
// first. Order matters: a revoked key also reports EXPKEYSIG on some
// configurations, and "revoked" is the more useful answer.
var gpgStatusReasons = []struct {
	status string
	reason string
}{
	{"BADSIG", "the signature does not match the commit"},
	{"REVKEYSIG", "the signing key was revoked"},
	{"EXPKEYSIG", "the signing key has expired"},
	{"EXPSIG", "the signature has expired"},
	{"NO_PUBKEY", "signed by a key this service does not carry"},
	{"ERRSIG", "the signature could not be checked"},
}

// verifyReason turns gpg's raw status output into a human explanation, or the
// empty string when nothing recognizable was reported.
func verifyReason(detail string) string {
	seen := make(map[string]bool)
	for _, line := range strings.Split(detail, "\n") {
		rest, found := strings.CutPrefix(strings.TrimSpace(line), gpgStatusPrefix)
		if !found {
			continue
		}
		seen[strings.SplitN(rest, " ", 2)[0]] = true
	}
	for _, candidate := range gpgStatusReasons {
		if seen[candidate.status] {
			return candidate.reason
		}
	}
	return ""
}

// keyring imports the armored public key into a throwaway GNUPGHOME used only
// for this run's verification. Verifying against the caller's own keyring would
// accept any key they happen to trust, which is the opposite of the question
// being asked: does *this service's* key cover the commit?
//
// The caller owns the returned directory and must remove it.
func keyring(ctx context.Context, armored []byte) (string, error) {
	home, err := os.MkdirTemp("", "gpg-sign-verify-")
	if err != nil {
		return "", fmt.Errorf("could not create a temporary keyring: %w", err)
	}
	// gpg refuses to use a homedir other users can read.
	// #nosec G302 -- this is a directory, which needs the execute bit to be usable.
	if err := os.Chmod(home, 0o700); err != nil {
		_ = os.RemoveAll(home)
		return "", fmt.Errorf("could not secure the temporary keyring: %w", err)
	}

	_, importErr, _ := capture(ctx, command{
		program: gpgProgram,
		args:    gpgArgs(home, "--quiet", "--import"),
		stdin:   armored,
	})

	// gpg --import exits 0 on garbage input often enough that the listing, not
	// the exit status, is the real check.
	listing, _, _ := capture(ctx, command{
		program: gpgProgram,
		args:    gpgArgs(home, "--list-keys", "--with-colons"),
	})
	if !bytes.HasPrefix(listing, []byte("pub:")) && !bytes.Contains(listing, []byte("\npub:")) {
		_ = os.RemoveAll(home)
		return "", fmt.Errorf("could not import the public key: %s", strings.TrimSpace(string(importErr)))
	}
	return home, nil
}

// keyIdentities returns the lowercased e-mail addresses the key claims. A
// commit is "ours" when its committer matches one of them.
func keyIdentities(ctx context.Context, armored []byte) (map[string]bool, error) {
	listing, err := run(ctx, command{
		program: gpgProgram,
		args:    []string{"--show-keys", "--with-colons"},
		stdin:   armored,
	})
	if err != nil {
		return nil, err
	}

	emails := make(map[string]bool)
	for _, line := range strings.Split(string(listing), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 10 || fields[0] != "uid" {
			continue
		}
		open := strings.LastIndex(fields[9], "<")
		if open < 0 {
			continue
		}
		emails[strings.ToLower(strings.TrimSuffix(fields[9][open+1:], ">"))] = true
	}

	if len(emails) == 0 {
		return nil, errors.New("the signing key carries no user ID with an email address")
	}
	return emails, nil
}
