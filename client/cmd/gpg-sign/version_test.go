package main

import (
	"bytes"
	"os"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"
)

// noBuildInfo is the build shape with nothing stamped at all: no VCS, no
// resolved module version. Everything the binary reports then came from the
// linker, which is what makes the ldflags cases below unambiguous.
func noBuildInfo() (*debug.BuildInfo, bool) { return nil, false }

// What `go build` stamps into a binary compiled from this checkout.
const (
	stampRevision = "7dbe1adbba4300509968fe5476d9f3988fa101a2"
	stampTime     = "2026-09-03T00:18:34Z"
)

// stampedBuildInfo is what `go build` puts in a binary compiled from a
// checkout: a placeholder module version and the three vcs settings.
func stampedBuildInfo(modified bool) func() (*debug.BuildInfo, bool) {
	dirty := "false"
	if modified {
		dirty = "true"
	}
	return func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{Version: devModule},
			Settings: []debug.BuildSetting{
				{Key: "vcs", Value: "git"},
				{Key: "vcs.revision", Value: stampRevision},
				{Key: "vcs.time", Value: stampTime},
				{Key: "vcs.modified", Value: dirty},
			},
		}, true
	}
}

// withBuildInfo pins what the toolchain stamped for the duration of a test.
// The suite has to state this rather than inherit it: the test binary running
// these assertions is itself built by `go test`, from a working tree that is
// dirty exactly when the developer is editing, so anything read from the real
// debug.ReadBuildInfo would make the expectations depend on the state of the
// checkout they run in.
func withBuildInfo(t *testing.T, info func() (*debug.BuildInfo, bool)) {
	t.Helper()

	previous := buildInfo
	t.Cleanup(func() { buildInfo = previous })
	buildInfo = info
}

// withBuildMetadata swaps the linker-set build metadata for the duration of a
// test and restores it afterwards, refreshing rootCmd.Version the way the
// package's init does. Build info is pinned to "nothing stamped" unless the
// test says otherwise, so a case that names only ldflags is about ldflags.
func withBuildMetadata(t *testing.T, ver, commit, built string) {
	t.Helper()

	withBuildInfo(t, noBuildInfo)

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
		clearRootBoolFlag(t, flagNameVersion)
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
	rootCmd.SetArgs([]string{flagVersion})

	code := -1
	out := captureStdout(t, func() { code = execute() })

	if code != 0 {
		t.Errorf("expected exit code 0 from --version, got %d", code)
	}
	if !strings.Contains(out, "9.9.9") {
		t.Errorf("expected injected version on stdout, got %q", out)
	}
}

// TestCaptureStdoutRestoresTheRealStdout is the isolation proof for the
// captureStdout helper this file shares with signcommit_test.go. A capture that
// leaks leaves every later test in the package writing into a pipe nobody
// reads, which surfaces as an unrelated failure somewhere else — so the
// property is asserted directly rather than inferred from the suite happening
// to pass.
func TestCaptureStdoutRestoresTheRealStdout(t *testing.T) {
	original := os.Stdout

	got := captureStdout(t, func() { _, _ = os.Stdout.WriteString("captured\n") })
	if got != "captured\n" {
		t.Errorf("expected the write to be captured, got %q", got)
	}
	if os.Stdout != original {
		t.Fatal("os.Stdout was not restored after the capture")
	}

	// A capture whose body fails still has to restore, which is the case a
	// deferless swap gets wrong. t.Cleanup runs on the subtest's own failure.
	t.Run("restores after a failing body", func(t *testing.T) {
		inner := t
		_ = captureStdout(inner, func() { inner.Log("body ran") })
	})
	if os.Stdout != original {
		t.Fatal("os.Stdout was not restored after a nested capture")
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
			commit:   testCommit,
			built:    metadataUnset,
			expected: testVersion + " (commit " + testCommit + ")",
		},
		{
			name:     "full release metadata",
			version:  testVersion,
			commit:   testCommit,
			built:    "2026-09-02T00:00:00Z",
			expected: testVersion + " (commit " + testCommit + ", built 2026-09-02T00:00:00Z)",
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

// TestVersionStringUsesGoBuildInfo is the shipping path. `.github/workflows/
// release.yml` injects only main.version, so on a downloaded release binary the
// commit and the build time have to come from what the toolchain stamped — and
// on a plain `go build` from a checkout, with no ldflags at all, so does
// everything except the version.
func TestVersionStringUsesGoBuildInfo(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		commit   string
		built    string
		info     func() (*debug.BuildInfo, bool)
		expected string
	}{
		{
			name:     "a release binary: version from ldflags, commit and time from the toolchain",
			version:  testVersion,
			commit:   metadataUnset,
			built:    metadataUnset,
			info:     stampedBuildInfo(false),
			expected: testVersion + " (commit " + stampRevision + ", built " + stampTime + ")",
		},
		{
			name:     "a bare go build from a checkout reports the revision it came from",
			version:  devVersion,
			commit:   metadataUnset,
			built:    metadataUnset,
			info:     stampedBuildInfo(false),
			expected: devVersion + " (commit " + stampRevision + ", built " + stampTime + ")",
		},
		{
			name:     "a dirty tree is marked, because the binary is not that commit",
			version:  devVersion,
			commit:   metadataUnset,
			built:    metadataUnset,
			info:     stampedBuildInfo(true),
			expected: devVersion + " (commit " + stampRevision + dirtySuffix + ", built " + stampTime + ")",
		},
		{
			name:     "the linker wins: an injected commit is not overwritten by the stamp",
			version:  testVersion,
			commit:   testCommit,
			built:    "2026-01-01T00:00:00Z",
			info:     stampedBuildInfo(false),
			expected: testVersion + " (commit " + testCommit + ", built 2026-01-01T00:00:00Z)",
		},
		{
			name:     "an injected commit built from a dirty tree is still dirty",
			version:  testVersion,
			commit:   testCommit,
			built:    "2026-01-01T00:00:00Z",
			info:     stampedBuildInfo(true),
			expected: testVersion + " (commit " + testCommit + dirtySuffix + ", built 2026-01-01T00:00:00Z)",
		},
		{
			name:    "(devel) is a placeholder, not a version",
			version: devVersion,
			commit:  metadataUnset,
			built:   metadataUnset,
			info: func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{Main: debug.Module{Version: devModule}}, true
			},
			expected: devVersion,
		},
		{
			name:    "a genuinely resolved module version is used when the linker was silent",
			version: devVersion,
			commit:  metadataUnset,
			built:   metadataUnset,
			info: func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{Main: debug.Module{Version: "v" + testVersion}}, true
			},
			expected: testVersion,
		},
		{
			name:    "a resolved module version does not override the linker",
			version: "4.5.6",
			commit:  metadataUnset,
			built:   metadataUnset,
			info: func() (*debug.BuildInfo, bool) {
				return &debug.BuildInfo{Main: debug.Module{Version: "v" + testVersion}}, true
			},
			expected: "4.5.6",
		},
		{
			name:     "no build info at all is still a usable answer",
			version:  devVersion,
			commit:   metadataUnset,
			built:    metadataUnset,
			info:     noBuildInfo,
			expected: devVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withBuildMetadata(t, tt.version, tt.commit, tt.built)
			withBuildInfo(t, tt.info)

			if got := versionString(); got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

// TestVersionStringIsDeterministic guards the release-binary property: the
// rendered version depends on the ldflags and the stamp and nothing else, so
// two calls in the same binary cannot disagree.
func TestVersionStringIsDeterministic(t *testing.T) {
	withBuildMetadata(t, testVersion, testCommit, "2026-09-02T00:00:00Z")

	if first, second := versionString(), versionString(); first != second {
		t.Errorf("versionString is not deterministic: %q then %q", first, second)
	}
}

// TestVersionShorthandIsNotSpent is the reservation. Cobra's
// InitDefaultVersionFlag registers `-v` for --version whenever nothing else
// claims the shorthand, and nothing on this root does — so `-v` would become
// part of the CLI's compatibility surface by default rather than by decision,
// and reclaiming it for --verbose later would be a breaking change. Registering
// the flag in version.go's init makes Cobra's default a no-op; this asserts the
// outcome rather than the mechanism.
func TestVersionShorthandIsNotSpent(t *testing.T) {
	resetRootCommand(t)
	rootCmd.InitDefaultVersionFlag()

	if f := rootCmd.Flags().Lookup(flagNameVersion); f == nil {
		t.Fatal("--version is not registered on the root command")
	} else if f.Shorthand != "" {
		t.Errorf("--version claims the -%s shorthand; it is reserved for a future --verbose", f.Shorthand)
	}
	if f := rootCmd.Flags().ShorthandLookup("v"); f != nil {
		t.Errorf("-v is taken by --%s; it is reserved for a future --verbose", f.Name)
	}

	// The flag being unregistered is the other way to have no shorthand, and it
	// would silently drop --version altogether.
	output, err := runRootArgs(t, "-v")
	if err == nil {
		t.Fatalf("-v was accepted, output: %q", output)
	}
	if !strings.Contains(err.Error(), "unknown shorthand flag") {
		t.Errorf("expected an unknown-shorthand error for -v, got %v", err)
	}
}

// TestHelpDescribesTheVersionFlagWithoutAShorthand keeps `--help` and
// docs/cli.md's flag table telling the same story: the table is the canonical
// reference, and a shorthand that appears only in --help would make it wrong.
func TestHelpDescribesTheVersionFlagWithoutAShorthand(t *testing.T) {
	output, err := runRootArgs(t, flagHelp)
	if err != nil {
		t.Fatalf("--help returned an error: %v", err)
	}

	if !strings.Contains(output, flagVersion) {
		t.Errorf("--help does not mention %s, got %q", flagVersion, output)
	}
	if regexp.MustCompile(`-[a-zA-Z], --version`).MatchString(output) {
		t.Errorf("--help advertises a shorthand for --version, got %q", output)
	}
}

// declaredSymbols is the set of package-main vars a `-X main.<name>=` may name,
// with the var it names. Anything else is dropped by the linker in silence.
func declaredSymbols() map[string]*string {
	return map[string]*string{
		symbolVersion: &version,
		"commitHash":  &commitHash,
		"buildTime":   &buildTime,
	}
}

var ldflagTarget = regexp.MustCompile(`-X main\.([A-Za-z_][A-Za-z0-9_]*)=`)

// ldflagProblems reports what is wrong with one build path's injection set.
//
// `required` is the set of symbols this path has to inject; a symbol that is
// declared but not required is one this path deliberately leaves to Go's build
// info, and injecting it anyway is reported too. Split out from the tests below
// so the guard itself can be driven with fixtures rather than only with the two
// real files — a drift check that had quietly stopped seeing anything would
// otherwise report both of them clean.
func ldflagProblems(name, content string, required map[string]bool) []string {
	declared := declaredSymbols()
	problems := []string{}

	targets := ldflagTarget.FindAllStringSubmatch(content, -1)
	if len(targets) == 0 && len(required) > 0 {
		return []string{name + " injects no -X main.* ldflags at all"}
	}

	injected := map[string]bool{}
	for _, target := range targets {
		symbol := target[1]
		injected[symbol] = true
		if _, ok := declared[symbol]; !ok {
			problems = append(problems,
				name+" injects -X main."+symbol+", which no var in package main declares, so the linker drops it in silence")
			continue
		}
		if !required[symbol] {
			problems = append(problems,
				name+" injects -X main."+symbol+", which this build path deliberately leaves to Go's build info")
		}
	}

	for symbol := range required {
		if _, ok := declared[symbol]; !ok {
			problems = append(problems, name+" is expected to inject main."+symbol+", which package main does not declare")
			continue
		}
		if !injected[symbol] {
			problems = append(problems, name+" no longer injects main."+symbol)
		}
	}

	return problems
}

// developerBuild and shippingBuild are the two build paths that produce a
// binary anybody runs, and the symbols each is responsible for.
//
// The shipping path injects only the version: `go build` already stamps
// vcs.revision and vcs.time into every binary it produces from a checkout, and
// versionString reads them, so the commit and the build time are supplied by
// the toolchain rather than by a linker flag. The version is the one thing the
// toolchain cannot supply, because client/go.mod's `replace` closes the
// `go install path@version` route that would set Main.Version.
var (
	developerBuild = struct {
		name     string
		path     string
		required map[string]bool
	}{
		name:     "client/Taskfile.yml",
		path:     "../../Taskfile.yml",
		required: map[string]bool{symbolVersion: true, "commitHash": true, "buildTime": true},
	}
	shippingBuild = struct {
		name     string
		path     string
		required map[string]bool
	}{
		name:     ".github/workflows/release.yml",
		path:     "../../../.github/workflows/release.yml",
		required: map[string]bool{symbolVersion: true},
	}
)

// TestLdflagsTargetDeclaredSymbols is the drift check for the bug this change
// fixes, across BOTH build paths. `-X main.foo=` naming a symbol no file
// declares is not an error: the linker drops it silently and the binary reports
// the default. The developer build was the only path the first version of this
// test read, and it was green on a tree where every binary a user could
// download answered "dev" — so the shipping path is read here too.
func TestLdflagsTargetDeclaredSymbols(t *testing.T) {
	for _, build := range []struct {
		name     string
		path     string
		required map[string]bool
	}{developerBuild, shippingBuild} {
		t.Run(build.name, func(t *testing.T) {
			content, err := os.ReadFile(build.path)
			if err != nil {
				t.Fatalf("failed to read %s: %v", build.name, err)
			}
			for _, problem := range ldflagProblems(build.name, string(content), build.required) {
				t.Error(problem)
			}
		})
	}
}

// TestLdflagProblemsDetectsDrift is the mutation test for the guard above. Each
// case is the real injection line with one edit, and the guard has to object to
// every one of them — otherwise the check is a comment that runs.
func TestLdflagProblemsDetectsDrift(t *testing.T) {
	const (
		release   = `LDFLAGS="-s -w -X main.version=${RELEASE_TAG#v}"`
		developer = `go build -trimpath -o bin/gpg-sign ` +
			`-ldflags "-s -w -X main.commitHash={{.COMMIT_HASH}} -X main.buildTime={{.BUILD_TIME}} -X main.version={{.VERSION}}"`
	)

	tests := []struct {
		name     string
		content  string
		required map[string]bool
		want     string
	}{
		{
			name:     "the shipping build as it stands is clean",
			content:  release,
			required: shippingBuild.required,
			want:     "",
		},
		{
			name:     "the developer build as it stands is clean",
			content:  developer,
			required: developerBuild.required,
			want:     "",
		},
		{
			name:     "the shipping build stops injecting the version",
			content:  `LDFLAGS="-s -w"`,
			required: shippingBuild.required,
			want:     "injects no -X main.* ldflags at all",
		},
		{
			name:     "the shipping build injects a misspelled symbol",
			content:  `LDFLAGS="-s -w -X main.verison=${RELEASE_TAG#v}"`,
			required: shippingBuild.required,
			want:     "which no var in package main declares",
		},
		{
			name:     "the shipping build starts injecting what the toolchain stamps",
			content:  `LDFLAGS="-s -w -X main.version=x -X main.buildTime=y"`,
			required: shippingBuild.required,
			want:     "deliberately leaves to Go's build info",
		},
		{
			name:     "the shipping build injects something else instead of the version",
			content:  `LDFLAGS="-s -w -X main.commitHash=${GITHUB_SHA}"`,
			required: shippingBuild.required,
			want:     "no longer injects main.version",
		},
		{
			name:     "the developer build drops one of its three",
			content:  `-ldflags "-X main.commitHash=a -X main.version=b"`,
			required: developerBuild.required,
			want:     "no longer injects main.buildTime",
		},
		{
			name:     "a symbol that was renamed in Go but not in the build",
			content:  `-ldflags "-X main.buildStamp=a"`,
			required: map[string]bool{"buildStamp": true},
			want:     "which package main does not declare",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			problems := ldflagProblems("fixture", tt.content, tt.required)

			if tt.want == "" {
				if len(problems) > 0 {
					t.Errorf("expected no problems, got %v", problems)
				}
				return
			}
			if !strings.Contains(strings.Join(problems, "\n"), tt.want) {
				t.Errorf("expected a problem mentioning %q, got %v", tt.want, problems)
			}
		})
	}
}
