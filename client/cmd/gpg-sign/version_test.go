package main

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"
)

// withBuildMetadata swaps the linker-set build metadata for the duration of a
// test and restores it afterwards, refreshing rootCmd.Version the way the
// package's init does.
func withBuildMetadata(t *testing.T, ver, commit, built string) {
	t.Helper()

	previousVersion, previousCommit, previousBuilt := version, commitHash, buildTime
	previousRootVersion := rootCmd.Version
	t.Cleanup(func() {
		version, commitHash, buildTime = previousVersion, previousCommit, previousBuilt
		rootCmd.Version = previousRootVersion
	})

	version, commitHash, buildTime = ver, commit, built
	rootCmd.Version = versionString()
}

// clearRootBoolFlag puts one of Cobra's own root flags back to false. pflag
// keeps parsed values on the command, and rootCmd is package state shared with
// the whole suite, so a flag left set leaks across tests in both directions:
// TestRootCommand leaves --help true, and Cobra checks help before version, so
// a --version run that inherits it prints the help text instead. Resetting on
// the way in and on the way out keeps this file order-independent.
func clearRootBoolFlag(t *testing.T, name string) {
	t.Helper()

	f := rootCmd.Flags().Lookup(name)
	if f == nil {
		return
	}
	if err := f.Value.Set("false"); err != nil {
		t.Logf("failed to reset --%s flag: %v", name, err)
	}
	f.Changed = false
}

// resetRootCommand restores the shared rootCmd to a usable state, both now and
// after the test.
func resetRootCommand(t *testing.T) {
	t.Helper()

	reset := func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
		clearRootBoolFlag(t, "help")
		clearRootBoolFlag(t, fieldVersion)
	}
	reset()
	t.Cleanup(reset)
}

// runRootArgs executes the root command with the given args and returns what it
// wrote, along with the execution error.
func runRootArgs(t *testing.T, args ...string) (string, error) {
	t.Helper()

	resetRootCommand(t)

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs(args)

	err := rootCmd.Execute()
	return out.String(), err
}

// TestVersionFlagReportsInjectedVersion is the issue's acceptance check: the
// flag is recognised, it succeeds, and what it prints is the version the
// release ldflags injected rather than a second, hand-maintained string.
func TestVersionFlagReportsInjectedVersion(t *testing.T) {
	withBuildMetadata(t, testVersion, "0f1e2d3c4b5a6978", "2026-09-02T00:00:00Z")

	output, err := runRootArgs(t, flagVersion)
	if err != nil {
		t.Fatalf("--version returned an error: %v", err)
	}

	for _, want := range []string{"gpg-sign", testVersion, "0f1e2d3c4b5a6978", "2026-09-02T00:00:00Z"} {
		if !strings.Contains(output, want) {
			t.Errorf("expected %q in --version output, got %q", want, output)
		}
	}
}

// TestVersionFlagExitsZero covers the process-level contract rather than the
// command-level one: `gpg-sign --version` is a success, not the exit 1 that
// execute() returns for a command error.
func TestVersionFlagExitsZero(t *testing.T) {
	withBuildMetadata(t, "9.9.9", metadataUnset, metadataUnset)

	resetRootCommand(t)

	previousStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe error: %v", err)
	}
	os.Stdout = w
	rootCmd.SetArgs([]string{flagVersion})

	code := execute()

	if err := w.Close(); err != nil {
		t.Fatalf("close error: %v", err)
	}
	os.Stdout = previousStdout

	if code != 0 {
		t.Errorf("expected exit code 0 from --version, got %d", code)
	}

	var out bytes.Buffer
	if _, err := out.ReadFrom(r); err != nil {
		t.Fatalf("read error: %v", err)
	}
	if !strings.Contains(out.String(), "9.9.9") {
		t.Errorf("expected injected version on stdout, got %q", out.String())
	}
}

// TestVersionStringDevelopmentDefaults pins the no-ldflags build: `go run` and
// `go test` have to produce a usable, unadorned version rather than a line of
// "unknown"s.
func TestVersionStringDevelopmentDefaults(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		commit   string
		built    string
		expected string
	}{
		{
			name:     "no ldflags at all",
			version:  devVersion,
			commit:   metadataUnset,
			built:    metadataUnset,
			expected: devVersion,
		},
		{
			name:     "empty metadata is treated as unset",
			version:  testVersion,
			commit:   "",
			built:    "",
			expected: testVersion,
		},
		{
			name:     "commit only",
			version:  testVersion,
			commit:   "abcdef0",
			built:    metadataUnset,
			expected: testVersion + " (commit abcdef0)",
		},
		{
			name:     "full release metadata",
			version:  testVersion,
			commit:   "abcdef0",
			built:    "2026-09-02T00:00:00Z",
			expected: testVersion + " (commit abcdef0, built 2026-09-02T00:00:00Z)",
		},
		{
			name:     "missing version falls back",
			version:  "",
			commit:   metadataUnset,
			built:    metadataUnset,
			expected: metadataUnset,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withBuildMetadata(t, tt.version, tt.commit, tt.built)

			if got := versionString(); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

// TestVersionStringIsDeterministic guards the release-binary property: the
// rendered version depends on the ldflags and nothing else, so two calls in the
// same binary cannot disagree.
func TestVersionStringIsDeterministic(t *testing.T) {
	withBuildMetadata(t, testVersion, "abcdef0", "2026-09-02T00:00:00Z")

	if first, second := versionString(), versionString(); first != second {
		t.Errorf("versionString is not deterministic: %q then %q", first, second)
	}
}

// TestTaskfileLdflagsTargetDeclaredSymbols is the drift check for the bug this
// change fixes. `-X main.foo=` naming a symbol no file declares is not an
// error: the linker drops it silently and the binary reports the default. So
// every -X target in the build task is matched here against the vars that
// actually exist.
func TestTaskfileLdflagsTargetDeclaredSymbols(t *testing.T) {
	declared := map[string]*string{
		fieldVersion: &version,
		"commitHash": &commitHash,
		"buildTime":  &buildTime,
	}

	taskfile, err := os.ReadFile("../../Taskfile.yml")
	if err != nil {
		t.Fatalf("failed to read client/Taskfile.yml: %v", err)
	}

	targets := regexp.MustCompile(`-X main\.([A-Za-z_][A-Za-z0-9_]*)=`).FindAllStringSubmatch(string(taskfile), -1)
	if len(targets) == 0 {
		t.Fatal("client/Taskfile.yml injects no -X main.* ldflags; --version would report only defaults")
	}

	for _, target := range targets {
		if _, ok := declared[target[1]]; !ok {
			t.Errorf("client/Taskfile.yml injects -X main.%s, which no var in package main declares", target[1])
		}
	}

	for name := range declared {
		if !strings.Contains(string(taskfile), "-X main."+name+"=") {
			t.Errorf("main.%s is declared for ldflag injection but client/Taskfile.yml never sets it", name)
		}
	}
}
