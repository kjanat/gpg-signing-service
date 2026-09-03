package main

// Shared fixtures for the CLI test suite.
const (
	testEnvAPIURL = "http://env.com"
	testEnvToken  = "env-token"
	flagHelp      = "--help"
)

// The --version fixtures. The three spellings below are the same word in three
// namespaces that rename independently -- a health response's JSON field, a
// Cobra flag, and a Go symbol the linker rewrites -- so they are three
// constants. One shared constant would make renaming any of them silently drag
// the other two, which is a coupling goconst's counter would have invented
// rather than a concept.
const (
	flagVersion = "--version"
	// fieldVersion is the JSON key in a health response.
	fieldVersion = "version"
	// flagNameVersion is the Cobra flag, without its leading dashes.
	flagNameVersion = "version"
	// symbolVersion is the package-main var the release ldflags rewrite.
	symbolVersion = "version"
	testVersion   = "1.2.3"
	// testCommit is a short commit the linker is pretended to have injected.
	testCommit = "abcdef0"
)

// The environment git reads an identity from, and the name every fixture
// commit carries.
const (
	envAuthorName     = "GIT_AUTHOR_NAME"
	envAuthorEmail    = "GIT_AUTHOR_EMAIL"
	envCommitterName  = "GIT_COMMITTER_NAME"
	envCommitterEmail = "GIT_COMMITTER_EMAIL"
	fixtureName       = "Test"
)
