package gitsign

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
)

// gitProgram is the only external binary this package drives. Signature
// verification is in-process; see pgp.go.
const gitProgram = "git"

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
}

// repoEnv are the environment variables that select a repository out from
// under the working directory. git reads them before it looks at the current
// directory, so with GIT_DIR set — which is the case inside every hook, under
// "git rebase --exec", and under "git bisect run" — a subprocess given a
// working directory would still operate on the caller's repository.
var repoEnv = []string{
	"GIT_DIR",
	"GIT_COMMON_DIR",
	"GIT_WORK_TREE",
	"GIT_OBJECT_DIRECTORY",
	"GIT_ALTERNATE_OBJECT_DIRECTORIES",
	"GIT_INDEX_FILE",
	"GIT_NAMESPACE",
	"GIT_CEILING_DIRECTORIES",
}

// withoutRepoEnv drops the repository-selecting variables from an environment,
// leaving everything else — credentials, proxies, GIT_SSH — intact.
func withoutRepoEnv(environ []string) []string {
	kept := make([]string, 0, len(environ))
	for _, entry := range environ {
		name, _, found := strings.Cut(entry, "=")
		if found && slices.Contains(repoEnv, name) {
			continue
		}
		kept = append(kept, entry)
	}
	return kept
}

// capture runs the command and returns stdout and stderr regardless of exit
// status. Callers that only care about success should use run instead.
func capture(ctx context.Context, c command) (stdout, stderr []byte, err error) {
	// #nosec G204 -- the program is a fixed literal and the arguments are
	// built from constant git verbs plus revisions this package read back out
	// of the repository itself.
	cmd := exec.CommandContext(ctx, c.program, c.args...)
	cmd.Dir = c.dir
	if c.dir != "" {
		cmd.Env = withoutRepoEnv(os.Environ())
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
