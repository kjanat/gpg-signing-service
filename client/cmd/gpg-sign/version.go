package main

import "strings"

// Defaults for a binary linked without the release ldflags — an ordinary
// `go build`, `go run` or `go test` build. They are what keeps this file from
// being a second version source: nothing here has to be edited at release
// time, and the test suite needs no linker flags to run.
const (
	devVersion    = "dev"
	metadataUnset = "unknown"
)

// Build metadata. `client/Taskfile.yml`'s build task injects all three through
// `-ldflags "-X main.version=... -X main.commitHash=... -X main.buildTime=..."`,
// which is why they are vars with constant initializers: -X only rewrites a
// string var whose initializer the linker can see as a constant.
//
// Until this file existed those three -X flags named symbols no package
// declared, and the linker dropped them without a word.
var (
	version    = devVersion
	commitHash = metadataUnset
	buildTime  = metadataUnset
)

// versionString renders the value Cobra substitutes into its version template.
// The commit and build time are appended only when the linker actually set
// them, so a dev build reports "dev" rather than trailing two "unknown"s, and a
// release binary's output is a pure function of its ldflags — same flags, same
// bytes, no clock or environment read at runtime.
func versionString() string {
	details := make([]string, 0, 2)
	if commitHash != "" && commitHash != metadataUnset {
		details = append(details, "commit "+commitHash)
	}
	if buildTime != "" && buildTime != metadataUnset {
		details = append(details, "built "+buildTime)
	}

	name := version
	if name == "" {
		name = metadataUnset
	}
	if len(details) == 0 {
		return name
	}
	return name + " (" + strings.Join(details, ", ") + ")"
}

// A non-empty Version is the whole trigger: Cobra's InitDefaultVersionFlag
// registers `--version` (plus the `-v` shorthand, which nothing else on the
// root claims) only for a command that has one, which is why setting this field
// is all `--version` needs.
func init() {
	rootCmd.Version = versionString()
}
