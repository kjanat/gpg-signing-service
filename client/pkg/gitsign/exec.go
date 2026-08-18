package gitsign

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	// gitProgram and gpgProgram are the external binaries this package drives.
	gitProgram = "git"
	gpgProgram = "gpg"
)

// CommandError reports a subprocess that exited non-zero. It carries the
// program's own stderr, because a bare "exit status 128" says nothing about
// which revision git refused to resolve.
type CommandError struct {
	Program string
	Args    []string
	Stderr  string
	Err     error
}

func (e *CommandError) Error() string {
	invocation := strings.Join(append([]string{e.Program}, e.Args...), " ")
	if e.Stderr != "" {
		return fmt.Sprintf("%s failed: %s", invocation, e.Stderr)
	}
	return fmt.Sprintf("%s failed: %v", invocation, e.Err)
}

func (e *CommandError) Unwrap() error { return e.Err }

// command describes one subprocess invocation.
type command struct {
	program string
	args    []string
	dir     string
	stdin   []byte
	// env entries are appended to the caller's environment, so a single
	// GNUPGHOME override does not have to reconstruct PATH.
	env []string
}

// capture runs the command and returns stdout and stderr regardless of exit
// status. Callers that only care about success should use run instead; capture
// exists for git verify-commit, whose status lines are the point even when it
// exits non-zero.
func capture(ctx context.Context, c command) (stdout, stderr []byte, err error) {
	// #nosec G204 -- the program is a fixed literal and the arguments are
	// built from constant git verbs plus revisions this package read back out
	// of the repository itself.
	cmd := exec.CommandContext(ctx, c.program, c.args...)
	cmd.Dir = c.dir
	if len(c.env) > 0 {
		cmd.Env = append(os.Environ(), c.env...)
	}
	if c.stdin != nil {
		cmd.Stdin = bytes.NewReader(c.stdin)
	}

	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	return out.Bytes(), errOut.Bytes(), err
}

// run returns stdout, or a *CommandError carrying stderr.
func run(ctx context.Context, c command) ([]byte, error) {
	stdout, stderr, err := capture(ctx, c)
	if err != nil {
		return nil, &CommandError{
			Program: c.program,
			Args:    c.args,
			Stderr:  strings.TrimSpace(string(stderr)),
			Err:     err,
		}
	}
	return stdout, nil
}
