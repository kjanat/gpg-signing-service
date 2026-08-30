package main

// Shared fixtures for the CLI test suite.
const (
	testEnvAPIURL = "http://env.com"
	testEnvToken  = "env-token"
	flagHelp      = "--help"
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
