package gitsign

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// This package is only byte-faithful against the go-git the module's replace
// directive selects, and a replace directive stops at the module that writes
// it: Go ignores the directives of a module it merely depends on. An external
// module importing this package would therefore resolve the stock go-git named
// on the require line and reparent through the encoder that empties idents and
// moves dates — the exact damage TestUnsignedObjectNeedsThePinnedFork spells
// out, except silently, in someone else's history.
//
// Nothing in a comment prevents that. What prevents it is the directory: Go
// refuses an import of a path with an "internal" element from outside the
// subtree rooted at its parent, and refuses it in the compiler rather than in a
// review. These tests hold the parts of that arrangement the compiler cannot
// hold on its own — the path that makes the rule apply, the absence of a
// documented package that would hand the same code out anyway, and the absence
// of one that skips this package and reaches for go-git itself.

// The module the replace directive redirects, named once for the two guards
// that turn on it: the one that keeps it out of the published packages, and the
// one that reads the directive out of go.mod.
const goGitModule = "github.com/go-git/go-git/v6"

// moduleRoot returns the client module's directory and its module path, found
// by walking up from this file to the go.mod that declares it.
func moduleRoot(t *testing.T) (dir, module string) {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not name this test file")
	}

	for at := filepath.Dir(file); ; {
		manifest := filepath.Join(at, "go.mod")
		// #nosec G304 -- the path is this source file's own directory and its
		// ancestors, as the compiler recorded them.
		raw, err := os.ReadFile(manifest)
		if err == nil {
			for line := range strings.Lines(string(raw)) {
				if path, found := strings.CutPrefix(strings.TrimSpace(line), "module "); found {
					return at, strings.TrimSpace(path)
				}
			}
			t.Fatalf("%s declares no module path", manifest)
		}

		parent := filepath.Dir(at)
		if parent == at {
			t.Fatalf("no go.mod above %s", file)
		}
		at = parent
	}
}

// The import path has to carry an "internal" element, because that element is
// the whole mechanism. Moving this package back under pkg/ would compile, pass
// every other test in this file's directory, and reopen the hole in one commit.
func TestGitsignIsImportableOnlyInsideThisModule(t *testing.T) {
	dir, module := moduleRoot(t)

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not name this test file")
	}
	relative, err := filepath.Rel(dir, filepath.Dir(file))
	if err != nil {
		t.Fatalf("locating this package under %s: %v", dir, err)
	}

	path := module + "/" + filepath.ToSlash(relative)
	elements := strings.Split(path, "/")
	if !slices.Contains(elements, "internal") {
		t.Errorf("this package is importable as %q, which any module may import; "+
			"it is faithful only under the go.mod replace directive, which does not "+
			"reach a module that depends on this one, so it belongs beneath an "+
			"\"internal\" directory where the compiler refuses that import", path)
	}
}

// eachPublishedImport hands check every import path named by a .go file under
// pkg/, along with that file's slash-separated path relative to the module
// root, so a failure names the file a reader has to open.
//
// Test files are walked with the rest. A test under pkg/ that reaches for
// something these guards forbid is not a downstream build hazard by itself, but
// it is the package beneath it acquiring the dependency in the one place nobody
// reads as published surface.
func eachPublishedImport(t *testing.T, dir string, check func(where, imported string)) {
	t.Helper()

	published := filepath.Join(dir, "pkg")
	fileSet := token.NewFileSet()
	walked := 0

	err := filepath.WalkDir(published, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}

		parsed, err := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		walked++

		where, relErr := filepath.Rel(dir, path)
		if relErr != nil {
			where = path
		}
		for _, imported := range parsed.Imports {
			check(filepath.ToSlash(where), strings.Trim(imported.Path.Value, `"`))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", published, err)
	}

	// A walk that reads nothing reports no violations, which is how a guard
	// like this rots: pkg/ moves, the tree it names goes empty, and every test
	// resting on it keeps passing while checking nothing at all.
	if walked == 0 {
		t.Fatalf("no .go files under %s; these guards only mean anything while "+
			"that directory is where the published packages live", published)
	}
}

// An internal package that a documented one re-exports is not internal in any
// sense that matters. pkg/ is what this repository publishes as a Go library —
// pkg/client is the SDK the docs point at, pkg/api the generated transport —
// and neither has any business reaching in here.
func TestNoPublishedPackageReExportsGitsign(t *testing.T) {
	dir, module := moduleRoot(t)
	forbidden := module + "/internal/gitsign"

	eachPublishedImport(t, dir, func(where, imported string) {
		if imported != forbidden {
			return
		}
		t.Errorf("%s imports %s; a package under pkg/ is part of this "+
			"repository's published Go surface, and re-exporting the "+
			"reparenting code through it hands a downstream build the "+
			"stock go-git this package cannot be trusted on", where, forbidden)
	})
}

// The import cycle and the internal rule between them make the re-export above
// hard to write by accident. Going around this package is not: a published
// pkg/rewrite that imports plumbing/object and reparents commits itself needs
// nothing from here, compiles against the fork inside this module because the
// replace directive is this module's, and resolves the stock go-git named on
// the require line for everyone who depends on this one. Same lost idents, same
// moved dates, no internal path anywhere in the failure.
//
// So the guard is on the dependency rather than on the route to it: no
// published package imports go-git, at the module root or any path beneath it.
// The fork is a private build detail of this module, and pkg/client — the SDK
// the docs point at — asks nothing of go-git to begin with.
func TestNoPublishedPackageImportsGoGit(t *testing.T) {
	dir, _ := moduleRoot(t)

	eachPublishedImport(t, dir, func(where, imported string) {
		if imported != goGitModule && !strings.HasPrefix(imported, goGitModule+"/") {
			return
		}
		t.Errorf("%s imports %s; go-git is byte-faithful here only through the "+
			"go.mod replace directive, which a module depending on this one "+
			"does not inherit, so a published package that names go-git "+
			"directly builds against stock go-git downstream — move the code "+
			"that needs it under internal/, where the compiler keeps it in", where, imported)
	})
}

// The replace directive itself, named rather than inferred.
//
// TestUnsignedObjectNeedsThePinnedFork catches its loss through the damage that
// follows, which is the check that matters and the one that would survive a
// rename. This one is cheaper and blunter: it reads the manifest and says which
// line is missing, so a directive dropped while editing go.mod fails as itself
// instead of as twelve rewritten commit headers.
func TestGoModReplacesGoGitWithTheFork(t *testing.T) {
	dir, _ := moduleRoot(t)

	// #nosec G304 -- dir is the module root moduleRoot just walked to.
	raw, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("reading go.mod: %v", err)
	}

	// The version is deliberately not asserted: rebasing the fork onto a newer
	// upstream go-git moves it, and that is maintenance rather than regression.
	// Which module the build takes go-git from is the invariant.
	const fork = "github.com/kjanat/go-git/v6"
	directive := "replace " + goGitModule + " => " + fork + " "
	if !strings.Contains(string(raw), directive) {
		t.Errorf("go.mod no longer carries %q; without it this package reparents "+
			"through released go-git, which empties idents it cannot place and "+
			"re-renders the ones it can", strings.TrimSpace(directive))
	}
}
