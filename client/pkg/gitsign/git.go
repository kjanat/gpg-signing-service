package gitsign

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
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

// cmd builds an unstarted git subprocess, for the streaming scan that cannot
// use the buffered helpers.
func (r *repo) cmd(ctx context.Context, args ...string) *exec.Cmd {
	return newCmd(ctx, command{program: gitProgram, args: args, dir: r.dir})
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

// revList returns the commits in base..head, parents before children. The
// upper bound is the commit the run captured rather than HEAD, so the range
// and the ref the update is guarded against are provably the same object.
func (r *repo) revList(ctx context.Context, base, head string) ([]string, error) {
	out, err := r.git(ctx, "rev-list", "--reverse", "--topo-order", base+".."+head)
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

// scanCommits streams "rev-list <head> | cat-file --batch" and hands each
// commit to visit, newest first. visit returning true stops the scan.
//
// The two processes are piped into each other and the records are parsed as
// they arrive, because the unbounded scan for the last signed commit walks all
// of reachable history: buffering it would cost hundreds of megabytes to answer
// a question the first record usually settles. One batch process rather than one
// per commit is what keeps the walk itself cheap.
func (r *repo) scanCommits(ctx context.Context, head string, limit int, visit func(batchObject) (bool, error)) error {
	// Stopping early leaves both processes mid-stream; cancelling is what
	// reaps them, and it also makes their exit status meaningless from there
	// on, which is why a satisfied scan ignores it.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	args := []string{"rev-list"}
	if limit > 0 {
		args = append(args, "--max-count="+strconv.Itoa(limit))
	}
	args = append(args, head)

	revisions := r.cmd(ctx, args...)
	batch := r.cmd(ctx, "cat-file", "--batch")

	feed, err := revisions.StdoutPipe()
	if err != nil {
		return err
	}
	batch.Stdin = feed

	objects, err := batch.StdoutPipe()
	if err != nil {
		return err
	}

	var revStderr, batchStderr strings.Builder
	revisions.Stderr = &revStderr
	batch.Stderr = &batchStderr

	if err := batch.Start(); err != nil {
		return &CommandError{Program: gitProgram, Args: batch.Args[1:], Err: err}
	}
	if err := revisions.Start(); err != nil {
		cancel()
		_ = batch.Wait()
		return &CommandError{Program: gitProgram, Args: args, Err: err}
	}

	stopped, scanErr := readBatch(objects, visit)
	if stopped || scanErr != nil {
		cancel()
		_ = batch.Wait()
		_ = revisions.Wait()
		return scanErr
	}

	if err := batch.Wait(); err != nil {
		return &CommandError{Program: gitProgram, Args: batch.Args[1:], Stderr: strings.TrimSpace(batchStderr.String()), Err: err}
	}
	if err := revisions.Wait(); err != nil {
		return &CommandError{Program: gitProgram, Args: args, Stderr: strings.TrimSpace(revStderr.String()), Err: err}
	}
	return nil
}

// readBatch parses "git cat-file --batch" output record by record. It reports
// whether visit asked to stop.
func readBatch(source io.Reader, visit func(batchObject) (bool, error)) (bool, error) {
	reader := bufio.NewReader(source)
	for {
		header, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && strings.TrimSpace(header) == "" {
				return false, nil
			}
			if !errors.Is(err, io.EOF) {
				return false, err
			}
		}

		fields := strings.Fields(header)
		// git answers an unresolvable name with "<name> missing", which is a
		// missing object rather than a parser disagreement.
		if len(fields) == 2 && fields[1] == "missing" {
			return false, fmt.Errorf("git cat-file --batch: %s is not in the object store", fields[0])
		}
		if len(fields) != 3 {
			return false, fmt.Errorf("git cat-file --batch: unexpected header %q", strings.TrimSuffix(header, "\n"))
		}
		size, err := strconv.Atoi(fields[2])
		if err != nil {
			return false, fmt.Errorf("git cat-file --batch: unreadable size %q: %w", fields[2], err)
		}

		raw := make([]byte, size)
		if _, err := io.ReadFull(reader, raw); err != nil {
			return false, fmt.Errorf("git cat-file --batch: truncated object body for %s: %w", fields[0], err)
		}
		// One trailing newline git adds after each body.
		if _, err := reader.Discard(1); err != nil && !errors.Is(err, io.EOF) {
			return false, err
		}

		stop, err := visit(batchObject{sha: fields[0], raw: raw})
		if err != nil {
			return false, err
		}
		if stop {
			return true, nil
		}
	}
}
