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

// updateRef moves HEAD to the given commit, but only if it still points at
// old. The run makes one network round-trip per commit, so the branch has a
// long window to move underneath it; without the compare-and-swap, a commit
// made in another terminal meanwhile would be discarded without a word.
func (r *repo) updateRef(ctx context.Context, sha, old string) error {
	_, err := r.git(ctx, "update-ref", detachedHead, sha, old)
	return err
}

// objectFormat returns the repository's hash algorithm, "sha1" or "sha256".
func (r *repo) objectFormat(ctx context.Context) (string, error) {
	return r.gitLine(ctx, "rev-parse", "--show-object-format")
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
