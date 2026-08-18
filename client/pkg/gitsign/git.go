package gitsign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// detachedHead is what "rev-parse --abbrev-ref HEAD" prints when no branch is
// checked out.
const detachedHead = "HEAD"

// verifyConfig pins the verifier the same way GNUPGHOME pins the keyring.
//
// A checkout that installed a sign-only gpg shim has gpg.program aimed at it,
// and that shim exits 1 on --verify, so ambient config would report every
// commit — including ones this key just signed — as unverified. minTrustLevel
// is the same trap through a different knob: the keyring is built by importing
// the key, so it carries no ownertrust, and any setting above the default
// rejects an otherwise good signature.
var verifyConfig = []string{
	"-c", "gpg.program=gpg",
	"-c", "gpg.format=openpgp",
	"-c", "gpg.minTrustLevel=undefined",
}

// repo runs git plumbing against one working tree.
type repo struct {
	dir string
}

// git runs a git subcommand and returns its stdout.
func (r *repo) git(ctx context.Context, args ...string) ([]byte, error) {
	return run(ctx, command{program: gitProgram, args: args, dir: r.dir})
}

// gitStdin runs a git subcommand with the given bytes on stdin.
func (r *repo) gitStdin(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	return run(ctx, command{program: gitProgram, args: args, dir: r.dir, stdin: stdin})
}

// gitLine runs a git subcommand expected to print exactly one value.
func (r *repo) gitLine(ctx context.Context, args ...string) (string, error) {
	out, err := r.git(ctx, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// currentBranch returns the checked-out branch, refusing a detached HEAD.
// Rewriting commits without a branch to move would leave the new objects
// unreachable the moment anything else updates HEAD.
func (r *repo) currentBranch(ctx context.Context) (string, error) {
	branch, err := r.gitLine(ctx, "rev-parse", "--abbrev-ref", detachedHead)
	if err != nil {
		return "", err
	}
	if branch == detachedHead {
		return "", errors.New("HEAD is detached; check out the branch you want signed")
	}
	return branch, nil
}

// head returns the commit HEAD points at.
func (r *repo) head(ctx context.Context) (string, error) {
	return r.gitLine(ctx, "rev-parse", detachedHead)
}

// resolveCommit resolves a ref to a commit SHA, failing if it names anything else.
func (r *repo) resolveCommit(ctx context.Context, ref string) (string, error) {
	return r.gitLine(ctx, "rev-parse", "--verify", ref+"^{commit}")
}

// mergeBase returns the fork point of HEAD and the given ref.
func (r *repo) mergeBase(ctx context.Context, ref string) (string, error) {
	return r.gitLine(ctx, "merge-base", detachedHead, ref)
}

// revList returns the commits in base..HEAD, parents before children.
func (r *repo) revList(ctx context.Context, base string) ([]string, error) {
	out, err := r.git(ctx, "rev-list", "--reverse", "--topo-order", base+".."+detachedHead)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// catFileCommit returns the raw commit object.
func (r *repo) catFileCommit(ctx context.Context, sha string) ([]byte, error) {
	return r.git(ctx, "cat-file", "commit", sha)
}

// hashObject writes a commit object and returns its SHA.
func (r *repo) hashObject(ctx context.Context, body []byte) (string, error) {
	out, err := r.gitStdin(ctx, body, "hash-object", "-t", "commit", "-w", "--stdin")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// updateRef moves HEAD to the given commit.
func (r *repo) updateRef(ctx context.Context, sha string) error {
	_, err := r.git(ctx, "update-ref", detachedHead, sha)
	return err
}

// verifyStatus reports whether the commit carries a signature the keyring in
// home accepts, alongside gpg's raw status output for diagnosis.
func (r *repo) verifyStatus(ctx context.Context, sha, home string) (bool, string) {
	args := make([]string, 0, len(verifyConfig)+3)
	args = append(args, verifyConfig...)
	args = append(args, "verify-commit", "--raw", sha)

	_, stderr, err := capture(ctx, command{
		program: gitProgram,
		args:    args,
		dir:     r.dir,
		env:     []string{"GNUPGHOME=" + home},
	})
	good := err == nil && bytes.Contains(stderr, []byte("[GNUPG:] GOODSIG"))
	return good, strings.TrimSpace(string(stderr))
}

// batchObject is one record from "git cat-file --batch".
type batchObject struct {
	sha string
	raw []byte
}

// catFileBatch streams the given revisions through a single git process. The
// scan for the last signed commit can walk an entire branch, and one
// subprocess per commit would dominate its runtime.
func (r *repo) catFileBatch(ctx context.Context, revisions []byte) ([]batchObject, error) {
	out, err := r.gitStdin(ctx, revisions, "cat-file", "--batch")
	if err != nil {
		return nil, err
	}

	var objects []batchObject
	for offset := 0; offset < len(out); {
		end := bytes.IndexByte(out[offset:], '\n')
		if end < 0 {
			return nil, errors.New("git cat-file --batch: truncated record header")
		}
		fields := strings.Fields(string(out[offset : offset+end]))
		if len(fields) != 3 {
			return nil, fmt.Errorf("git cat-file --batch: unexpected header %q", out[offset:offset+end])
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("git cat-file --batch: unreadable size %q: %w", fields[2], err)
		}

		offset += end + 1
		if offset+size > len(out) {
			return nil, errors.New("git cat-file --batch: truncated object body")
		}
		objects = append(objects, batchObject{sha: fields[0], raw: out[offset : offset+size]})
		// One trailing newline git adds after each body.
		offset += size + 1
	}
	return objects, nil
}
