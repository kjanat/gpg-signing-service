package main

import (
	"runtime/debug"
	"strings"
)

// Defaults for a binary linked without the release ldflags — an ordinary
// `go build`, `go run` or `go test` build. They are what keeps this file from
// being a second version source: nothing here has to be edited at release
// time, and the test suite needs no linker flags to run.
const (
	devVersion    = "dev"
	metadataUnset = "unknown"

	// devModule is what the module graph reports for a main package that was
	// not resolved through `go install path@version` — which is every build
	// this repository makes, since the `replace` in client/go.mod closes the
	// module-proxy route. It is a placeholder, not a version, so it is never
	// shown.
	devModule = "(devel)"

	// dirtySuffix marks a binary built from a tree that had uncommitted or
	// untracked content. The commit it names is then the commit it was built
	// NEAR, not the commit it is.
	dirtySuffix = "+dirty"

	// The two labels the timestamp can carry, because there are two different
	// quantities available and only one of them is a build time.
	//
	// labelBuilt is for a linker-injected main.buildTime: `client/Taskfile.yml`
	// fills it from `date -u`, so it is the moment of compilation.
	//
	// labelCommitted is for Go's vcs.time, which is documented as the
	// modification time associated with vcs.revision — the revision's commit
	// time, fixed when the commit was made and unrelated to when anybody
	// compiled it. The shipping build injects no buildTime, so a downloaded
	// release binary reports this one; rendering it as "built" would make the
	// same field mean two different things depending on which path produced the
	// binary, which is exactly what an install script diffing timestamps would
	// get wrong.
	labelBuilt     = "built"
	labelCommitted = "committed"
)

// Build metadata the linker may inject. `client/Taskfile.yml` sets all three
// for a developer build; `.github/workflows/release.yml` sets only
// `main.version`, from the tag being published, and leaves the commit and the
// build time to Go's own build info below.
//
// They are vars with constant initializers because that is what `-X` needs: it
// only rewrites a string var whose initializer the linker can see as a
// constant. Until this file existed those -X flags named symbols no package
// declared, and the linker dropped them without a word — which is what
// TestLdflagsTargetDeclaredSymbols now guards, for both build paths.
var (
	version    = devVersion
	commitHash = metadataUnset
	buildTime  = metadataUnset
)

// buildInfo is debug.ReadBuildInfo, indirected so the tests can pin what the
// toolchain stamped instead of asserting against whatever stamped the test
// binary that happens to be running them.
var buildInfo = debug.ReadBuildInfo

// isSet reports whether a metadata field carries a real value. Empty is the
// zero value of an -X target the linker never touched; metadataUnset is this
// file's own placeholder.
func isSet(value string) bool { return value != "" && value != metadataUnset }

// buildMetadata is the resolved answer for one binary: the linker's values
// where it spoke, Go's build info where it did not.
type buildMetadata struct {
	version string
	commit  string
	// timestamp and timestampLabel travel together because the timestamp alone
	// does not say what it is: it is a build time when the linker supplied it
	// and a commit time when the toolchain did. The label is carried rather
	// than derived at render time so the source cannot be lost between here and
	// the string.
	timestamp      string
	timestampLabel string
	dirty          bool
}

// resolveBuildMetadata merges the two sources of truth, linker first.
//
// A bare `go build` from a checkout already stamps vcs.revision, vcs.time and
// vcs.modified into every binary, so the commit and the build time are
// available without any ldflags at all — which is why the release workflow
// injects only the version and leaves these to the toolchain. Where -X did
// speak it wins outright: a release binary's version is the tag it was cut
// from, not whatever the module graph guessed.
func resolveBuildMetadata() buildMetadata {
	resolved := buildMetadata{
		version:        version,
		commit:         commitHash,
		timestamp:      buildTime,
		timestampLabel: labelBuilt,
	}

	info, ok := buildInfo()
	if !ok || info == nil {
		return resolved
	}

	// Only a genuinely resolved module version is a version. `go install
	// path@version` is the one build shape that sets it, and this module's
	// `replace` directive refuses that shape, so in practice this is dead
	// weight — kept because it costs one comparison and is the correct answer
	// if the replace ever goes away.
	if !isSet(resolved.version) || resolved.version == devVersion {
		if module := info.Main.Version; module != "" && module != devModule {
			resolved.version = strings.TrimPrefix(module, "v")
		}
	}

	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			if !isSet(resolved.commit) {
				resolved.commit = setting.Value
			}
		case "vcs.time":
			// Only when the linker was silent, and never under the "built"
			// label: this is the commit's timestamp, not the compilation's.
			if !isSet(resolved.timestamp) {
				resolved.timestamp = setting.Value
				resolved.timestampLabel = labelCommitted
			}
		case "vcs.modified":
			// Deliberately not gated on the linker having been silent: a tree
			// with uncommitted work is dirty whether or not somebody passed a
			// commit on the command line, and the injected SHA is exactly the
			// one the binary then does not correspond to.
			resolved.dirty = setting.Value == "true"
		}
	}

	return resolved
}

// versionString renders the value Cobra substitutes into its version template.
// The commit and the timestamp are appended only when one of the two sources
// supplied them, so a build with neither reports "dev" rather than trailing two
// "unknown"s. The timestamp names what it is — "built" or "committed" — because
// the two build paths supply different quantities for that one field.
func versionString() string {
	resolved := resolveBuildMetadata()

	details := make([]string, 0, 2)
	if isSet(resolved.commit) {
		commit := resolved.commit
		if resolved.dirty {
			commit += dirtySuffix
		}
		details = append(details, "commit "+commit)
	}
	if isSet(resolved.timestamp) {
		details = append(details, resolved.timestampLabel+" "+resolved.timestamp)
	}

	name := resolved.version
	if name == "" {
		name = metadataUnset
	}
	if len(details) == 0 {
		return name
	}
	return name + " (" + strings.Join(details, ", ") + ")"
}

// A non-empty Version is the whole trigger: Cobra's InitDefaultVersionFlag
// registers `--version` only for a command that has one.
//
// The flag is registered here rather than left to Cobra because Cobra's default
// takes the `-v` shorthand whenever nothing else claims it, and nothing on this
// root does. `-v` is the conventional spelling of `--verbose`, and handing it to
// `--version` is free now and a breaking change later; a flag named `version`
// that already exists makes InitDefaultVersionFlag a no-op, so `--version`
// keeps working and `-v` stays unspent. Cobra reads the flag by name, not by
// the registration that created it.
func init() {
	rootCmd.Flags().Bool("version", false, "Print the build version and exit")
	rootCmd.Version = versionString()
}
