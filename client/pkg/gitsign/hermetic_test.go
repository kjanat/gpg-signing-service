package gitsign

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures in this package are built by shelling out to git, so every
// question git answers from ambient state is a way for this suite to pass on
// the machine that wrote it and fail somewhere else. That is not hypothetical:
// TestRepairRefusesABaseTheTipDoesNotReach wrote a commit object with no
// identity pinned and was green for everyone who ran it locally and green in
// the Action that runs Claude — which exports GIT_AUTHOR_* and GIT_COMMITTER_*
// — while failing the plain Go CI job with "Author identity unknown".
//
// These tests hold the fixture environment to that standard directly, so the
// next helper that forgets is caught here rather than in someone's CI.

// clearAmbientGit removes the identity a host may be exporting, reproducing a
// clean CI runner inside a session that has one.
//
// t.Setenv cannot unset, and it is what registers the restore, so each variable
// is blanked through it first and then removed outright.
func clearAmbientGit(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		envAuthorName, envAuthorEmail, "GIT_AUTHOR_DATE",
		envCommitterName, envCommitterEmail, "GIT_COMMITTER_DATE",
		"EMAIL",
	} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("could not clear %s: %v", name, err)
		}
	}
}

// A git command that writes an object needs an identity, and on a clean runner
// there is none to guess from. The fixture helpers must supply one themselves.
func TestFixtureGitWritesObjectsWithoutAHostIdentity(t *testing.T) {
	requireGit(t)
	clearAmbientGit(t)
	// The host's config must not be able to supply one either, or this would
	// pass on a developer machine for the wrong reason.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	dir := initRepo(t)
	root := head(t, dir)

	// commit-tree is the bare case: no working tree, no config, just an object
	// write. This is the exact call that failed in CI.
	sha := git(t, dir, nil, "commit-tree", root+"^{tree}", "-p", root, "-m", "chore: no host identity")
	if sha == "" {
		t.Fatal("commit-tree produced no object")
	}

	author := git(t, dir, nil, "show", "--no-patch", "--format=%an <%ae>", sha)
	if author != fixtureName+" <"+serviceEmail+">" {
		t.Errorf("the fixture identity did not reach the object: %q", author)
	}
}

// A host that exports an identity must not be able to lend it to a fixture
// either, or a test asserting on authorship would read the developer's name.
//
// The commit is written with no caller environment on purpose. Going through
// commit() would name an identity that outranks the ambient one by itself,
// appended last and winning with or without the scrub, so the pin under test
// would never be the thing deciding and this would pass either way.
func TestFixtureGitIgnoresAnAmbientIdentity(t *testing.T) {
	requireGit(t)
	t.Setenv(envAuthorName, "Ambient")
	t.Setenv(envAuthorEmail, "ambient@example.invalid")
	t.Setenv(envCommitterName, "Ambient")
	t.Setenv(envCommitterEmail, "ambient@example.invalid")

	dir := initRepo(t)
	git(t, dir, nil, "commit", "--allow-empty", "-m", "chore: ambient")

	got := git(t, dir, nil, "show", "--no-patch", "--format=%an <%ae>|%cn <%ce>", head(t, dir))
	want := fixtureName + " <" + serviceEmail + ">|" + fixtureName + " <" + serviceEmail + ">"
	if got != want {
		t.Errorf("an ambient identity reached the fixture:\n got %s\nwant %s", got, want)
	}
}

// GIT_CONFIG_COUNT injects config that outranks every config file, so pinning
// GIT_CONFIG_GLOBAL is not on its own enough to isolate a fixture from its
// host. commit.gpgsign is the setting that matters most here: left on, every
// fixture commit would be signed by whatever key the host happens to hold.
func TestFixtureGitIgnoresInjectedHostConfig(t *testing.T) {
	requireGit(t)
	t.Setenv("GIT_CONFIG_COUNT", "2")
	t.Setenv("GIT_CONFIG_KEY_0", "commit.gpgsign")
	t.Setenv("GIT_CONFIG_VALUE_0", "true")
	t.Setenv("GIT_CONFIG_KEY_1", "user.email")
	t.Setenv("GIT_CONFIG_VALUE_1", "injected@example.invalid")

	dir := initRepo(t)
	sha := commit(t, dir, "chore: injected config", serviceEmail)

	if raw := gitRaw(t, dir, nil, "cat-file", "commit", sha); strings.Contains(string(raw), "gpgsig") {
		t.Errorf("injected config signed a fixture commit:\n%s", raw)
	}
	if email := git(t, dir, nil, "show", "--no-patch", "--format=%ae", sha); email != serviceEmail {
		t.Errorf("injected config chose the fixture's author: %q", email)
	}
}

// A global config file on the host must not reach a fixture either.
//
// The file is put where git finds it on its own rather than named through
// GIT_CONFIG_GLOBAL, because the scrub deletes that variable before git is
// started: pointed at through the environment, the hostile file is unreachable
// whether or not this package pins GIT_CONFIG_GLOBAL, and the guard would be
// held up by the scrub instead of by the pin it is named for.
//
// It is read back through a key of its own as well as the authorship, since
// user.name and user.email are settled by the environment long before a config
// file is consulted — an authorship assertion alone proves only that the
// identity is pinned, which the two tests above already cover.
func TestFixtureGitIgnoresAHostGlobalConfig(t *testing.T) {
	requireGit(t)

	home := t.TempDir()
	hostile := []byte("[user]\n\tname = Hostile\n\temail = hostile@example.invalid\n" +
		"[hostile]\n\tmarker = reached\n")
	if err := os.WriteFile(filepath.Join(home, ".gitconfig"), hostile, 0o600); err != nil {
		t.Fatalf("could not write the hostile config: %v", err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	dir := initRepo(t)
	git(t, dir, nil, "commit", "--allow-empty", "-m", "chore: hostile global config")

	if marker := git(t, dir, nil, "config", "--default", "", "--get", "hostile.marker"); marker != "" {
		t.Errorf("a host global config reached the fixture: hostile.marker is %q", marker)
	}
	got := git(t, dir, nil, "show", "--no-patch", "--format=%an <%ae>", head(t, dir))
	if want := fixtureName + " <" + serviceEmail + ">"; got != want {
		t.Errorf("a host global config chose the fixture's author:\n got %s\nwant %s", got, want)
	}
}

// The scrub is the mechanism the tests above rely on, so it is asserted
// directly: nothing named GIT_* survives from the host, what this package pins
// does, and the caller still gets the last word.
func TestGitEnvScrubsHostGitVariables(t *testing.T) {
	const callerAuthor = envAuthorName + "=Caller"

	t.Setenv(envAuthorName, "Ambient")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_TRACE", "1")

	env := gitEnv([]string{callerAuthor})

	for _, leaked := range []string{"GIT_TRACE=1", "GIT_CONFIG_COUNT=1", envAuthorName + "=Ambient"} {
		if occurrences(env, leaked) != 0 {
			t.Errorf("the host's %s survived the scrub", leaked)
		}
	}
	if got := occurrences(env, envAuthorName+"="+fixtureName); got != 1 {
		t.Errorf("the pinned identity appears %d time(s), want exactly 1", got)
	}
	if got := occurrences(env, callerAuthor); got != 1 {
		t.Errorf("the caller's override appears %d time(s), want exactly 1", got)
	}
	// Order decides which one git uses, and the caller has to be able to win.
	if last := lastValue(env, envAuthorName); last != "Caller" {
		t.Errorf("the caller's override does not win: %s resolves to %q", envAuthorName, last)
	}
}

// occurrences counts exact entries, since a duplicated pin would be as much a
// bug as a missing one.
func occurrences(env []string, entry string) int {
	total := 0
	for _, candidate := range env {
		if candidate == entry {
			total++
		}
	}
	return total
}

// lastValue returns the value git would use for a name: the last occurrence.
func lastValue(env []string, name string) string {
	value := ""
	for _, entry := range env {
		if strings.HasPrefix(entry, name+"=") {
			value = strings.TrimPrefix(entry, name+"=")
		}
	}
	return value
}
