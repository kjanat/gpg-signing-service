package gitsign

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
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
		where = filepath.ToSlash(where)
		for _, imported := range parsed.Imports {
			named, decoded := importPath(imported.Path.Value)
			if !decoded {
				// Unreachable through go/parser, which rejects the literals
				// strconv.Unquote refuses -- which is why it must not be
				// assumed away rather than reported. An import this walk
				// cannot read is an import it has not checked, and the whole
				// value of the walk is that it checked every one.
				t.Errorf("%s: import literal %s does not decode as a Go string; "+
					"these guards cannot say what it names", where, imported.Path.Value)
				continue
			}
			check(where, named)
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
		if !namesGoGit(imported) {
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

// --- reading an import, and reading the whole graph --------------------------

// importPath is the path the compiler takes from one import literal. Go's
// grammar puts a *string literal* there and means the string it denotes, not
// the bytes between the outermost quote characters: `"github.com/go-git/go-git/v6"`,
// the same path in backticks, and "github.com/go-git/go-\x67it/v6" are three
// spellings of one import, and the last two are ordinary, compiling Go.
//
// Trimming quote characters — what these guards did — decodes exactly the first
// spelling. The other two arrived at the comparison still carrying backticks or
// still spelling "git" as "go-\x67it", matched nothing forbidden, and were
// reported as a clean pkg/. TestPublishedImportWalkDecodesImportLiterals puts
// every spelling through the same guard.
func importPath(literal string) (string, bool) {
	path, err := strconv.Unquote(literal)
	if err != nil {
		return "", false
	}
	return path, true
}

// namesGoGit reports whether an import path or a graph node is the forked
// module or anything beneath it.
func namesGoGit(path string) bool {
	return path == goGitModule || strings.HasPrefix(path, goGitModule+"/")
}

// The literals the trimming reader walked past, put through the walk that reads
// pkg/. Each file below is valid Go naming exactly the module goGitModule
// names, and each one used to leave TestNoPublishedPackageImportsGoGit green.
func TestPublishedImportWalkDecodesImportLiterals(t *testing.T) {
	module := t.TempDir()
	spellings := map[string]string{
		// The plain form, which trimming did read.
		"plain.go": `import "` + goGitModule + `"`,
		// A raw string literal. Nothing about an import path forbids one, and
		// gofmt leaves it alone.
		"raw.go": "import `" + goGitModule + "`",
		// A basic string literal spelled with Go's own escapes: \x67 is "g"
		// and \u0069 is "i", so the bytes on disk share no substring with the
		// path they denote past "github.com/go-".
		"escaped.go": `import "github.com/go-g\x69t/go-\x67\u0069t/v6"`,
		// Two hops down, to keep the prefix half of namesGoGit honest.
		"beneath.go": `import "github.com/go-git/go-g\x69t/v6/plumbing/object"`,
	}

	dir := filepath.Join(module, "pkg", "rewrite")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("building the fixture tree: %v", err)
	}
	for name, imports := range spellings {
		source := "package rewrite\n\n" + imports + "\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}

	decoded := map[string]string{}
	eachPublishedImport(t, module, func(where, imported string) {
		decoded[filepath.Base(where)] = imported
	})

	if len(decoded) != len(spellings) {
		t.Fatalf("the walk read %d of the %d fixture files", len(decoded), len(spellings))
	}
	for name, imported := range decoded {
		if !namesGoGit(imported) {
			t.Errorf("%s decodes to %q, which the go-git guard does not recognise; "+
				"the file imports go-git in valid Go and would build against it",
				name, imported)
		}
	}

	// The bypass itself, stated rather than implied: the reader this replaced
	// compared the bytes between the outermost quote characters, and for every
	// file here but plain.go that string is not the import path.
	for name, literal := range map[string]string{
		"raw.go":     "`" + goGitModule + "`",
		"escaped.go": `"github.com/go-g\x69t/go-\x67\u0069t/v6"`,
	} {
		if trimmed := strings.Trim(literal, `"`); namesGoGit(trimmed) {
			t.Errorf("%s no longer models the bypass: trimming quote characters "+
				"off %s already yields a path the go-git guard recognises", name, literal)
		}
	}
	if got := decoded["raw.go"]; got != goGitModule {
		t.Errorf("a backtick-quoted import decoded to %q, want %q", got, goGitModule)
	}
	if got := decoded["escaped.go"]; got != goGitModule {
		t.Errorf("an escaped import decoded to %q, want %q", got, goGitModule)
	}
}

// A literal go/parser would never hand the walk, kept as a case anyway: the
// walk's contract is that it either reads an import or says it could not, and
// "could not" has to stay distinguishable from "found nothing forbidden".
func TestImportPathRefusesALiteralItCannotDecode(t *testing.T) {
	for _, literal := range []string{``, `"unterminated`, `"\q"`, `github.com/go-git/go-git/v6`} {
		if path, decoded := importPath(literal); decoded {
			t.Errorf("importPath(%q) decoded to %q; it is not a Go string literal", literal, path)
		}
	}
}

// --- the targets the closure has to be resolved for ---------------------------
//
// `go list` answers for one platform: the one it is running on, unless GOOS and
// GOARCH say otherwise. Build constraints are part of that answer, so a closure
// resolved for the host says nothing about the others. An internal wrapper
// whose only go-git import sits behind //go:build windows leaves every guard in
// this file green on a Linux runner and ships stock go-git in a third of the
// binaries a release uploads — the bypass of the paragraph below, wearing a
// build tag and costing one line to write.
//
// So the closure is resolved once per released target. The list lives here
// rather than being read out of the workflow at run time, because a guard whose
// subject is parsed out of YAML stops guarding the moment the YAML is
// reorganised, and stops loudly only if you were lucky.
// TestReleaseTargetsMatchTheReleaseWorkflow reads the workflow instead and
// fails when the two disagree, which turns drift into one failing test naming
// both lists rather than a silently narrowed search.

// releaseWorkflow builds and uploads the client binaries, and is the authority
// on which platforms this repository is on the hook for.
const releaseWorkflow = ".github/workflows/release.yml"

// releaseTarget is one GOOS/GOARCH pair releaseWorkflow builds the client for.
type releaseTarget struct {
	goos, goarch string
}

func (target releaseTarget) String() string { return target.goos + "/" + target.goarch }

// The targets of releaseWorkflow's "Build binaries" step, kept in step with it
// by TestReleaseTargetsMatchTheReleaseWorkflow. GOARCH is carried as well as
// GOOS because a constraint can name either, and `_arm64.go` hides an import
// from an amd64 runner exactly as well as `_windows.go` hides one from Linux.
var releaseTargets = []releaseTarget{
	{goos: "linux", goarch: amd64},
	{goos: "linux", goarch: arm64},
	{goos: "darwin", goarch: amd64},
	{goos: "darwin", goarch: arm64},
	{goos: "windows", goarch: amd64},
	{goos: "windows", goarch: arm64},
}

// Named only because every line of the list above would otherwise repeat them.
const (
	amd64 = "amd64"
	arm64 = "arm64"
)

// hostTarget is what `go list` resolves for with no GOOS or GOARCH in its
// environment: the one target the closure used to be read for.
func hostTarget() releaseTarget {
	return releaseTarget{goos: runtime.GOOS, goarch: runtime.GOARCH}
}

// repoRoot walks up from the client module to the directory the workflows live
// in, so the drift check reads the release.yml a release would run.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, _ := moduleRoot(t)
	for at := dir; ; {
		if _, err := os.Stat(filepath.Join(at, releaseWorkflow)); err == nil {
			return at
		}

		parent := filepath.Dir(at)
		if parent == at {
			t.Fatalf("no %s above %s; this check cannot read the target list it exists "+
				"to compare releaseTargets against, and a comparison against nothing "+
				"must not pass", releaseWorkflow, dir)
		}
		at = parent
	}
}

// release.yml names its targets twice — once in the loop that builds them, once
// in the list of assets it uploads — and releaseTargets names them a third
// time. All three have to agree. A target the release builds and this file omits
// is a binary whose published-package closure nothing resolves; one this file
// carries and the release does not is a check nobody asked for, which is the
// cheaper mistake but still worth knowing about.
func TestReleaseTargetsMatchTheReleaseWorkflow(t *testing.T) {
	// #nosec G304 -- a fixed path beneath the repository root this test walked to.
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), releaseWorkflow))
	if err != nil {
		t.Fatalf("reading %s: %v", releaseWorkflow, err)
	}

	built, uploaded := workflowTargets(string(raw))

	// Both directions this reader can come back empty are failures, not
	// agreement: the build step reorganised into a matrix, or the assets
	// renamed. Either way the drift check has stopped reading the list it
	// compares against, and the empty set agrees with nothing.
	if len(built) == 0 {
		t.Fatalf("no `for target in GOOS/GOARCH ...` loop found in %s; releaseTargets is "+
			"unverified, and the closure may be resolved for targets the release no "+
			"longer builds — or miss ones it does", releaseWorkflow)
	}
	if len(uploaded) == 0 {
		t.Fatalf("no dist/gpg-sign-GOOS-GOARCH assets found in %s; the second list this "+
			"check reads is no longer where it reads it", releaseWorkflow)
	}

	declared := make([]string, 0, len(releaseTargets))
	for _, target := range releaseTargets {
		declared = append(declared, target.String())
	}
	slices.Sort(declared)
	slices.Sort(built)
	slices.Sort(uploaded)

	if !slices.Equal(declared, built) {
		t.Errorf("releaseTargets is %v and %s builds %v; the dependency closure is "+
			"resolved for the former, so every target only in the latter ships "+
			"unchecked", declared, releaseWorkflow, built)
	}
	if !slices.Equal(built, uploaded) {
		t.Errorf("%s builds %v and uploads %v; one of its two lists has drifted from "+
			"the other, and this file cannot be in step with both", releaseWorkflow, built, uploaded)
	}
}

// workflowTargets reads the two places release.yml names its targets: the
// `for target in ...` loop of the build step and the asset names of the release
// step. Deliberately shallow, and deliberately not a YAML parser — it is a
// drift detector, and anything it cannot read it reports as nothing read, which
// its one caller fails on.
func workflowTargets(workflow string) (built, uploaded []string) {
	const (
		loop  = "for target in "
		asset = "dist/gpg-sign-"
	)

	for line := range strings.Lines(workflow) {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, loop):
			list, _, _ := strings.Cut(strings.TrimPrefix(line, loop), ";")
			for target := range strings.FieldsSeq(list) {
				if goos, goarch, ok := strings.Cut(target, "/"); ok {
					built = append(built, goos+"/"+goarch)
				}
			}
		case strings.HasPrefix(line, asset):
			name := strings.TrimSuffix(strings.TrimPrefix(line, asset), ".exe")
			if goos, goarch, ok := strings.Cut(name, "-"); ok {
				uploaded = append(uploaded, goos+"/"+goarch)
			}
		}
	}

	return built, uploaded
}

// --- the dependency closure --------------------------------------------------
//
// TestNoPublishedPackageImportsGoGit above reads the import lines of the files
// under pkg/ and nothing else, which is one edge of the graph. The hazard is
// the whole path: a published pkg/client importing an internal wrapper that
// imports plumbing/object hands a downstream build the stock go-git just as
// surely as naming it outright, and no file under pkg/ mentions go-git anywhere
// in that arrangement. So the invariant is on reachability — nothing the
// published packages can reach, at any depth, is go-git — and it is read out of
// `go list`, which resolves build tags, cgo, generated files and the module
// graph the way the build does, rather than out of a second import walker
// written here that would agree with the compiler only by luck.

// listedPackage is the slice of `go list -json` these guards read: one node of
// the import graph, and the edges leaving it.
type listedPackage struct {
	ImportPath string
	Imports    []string
}

// goList runs `go list` in dir, for one target, and decodes the object stream
// it writes.
//
// The target is the whole point of the signature. `go list` resolves build
// constraints for the platform it is asked about and no other, so which
// platform it is asked about decides what the graph below contains.
func goList(dir string, target releaseTarget, args ...string) ([]listedPackage, error) {
	// #nosec G204 -- args are the fixed flag lists written at the call sites
	// below; dir is a module root this test walked to.
	command := exec.Command("go", append([]string{"list", "-json=ImportPath,Imports"}, args...)...)
	command.Dir = dir
	command.Env = append(os.Environ(), "GOOS="+target.goos, "GOARCH="+target.goarch)

	var stderr bytes.Buffer
	command.Stderr = &stderr

	out, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("go list %s in %s for %s: %w\n%s",
			strings.Join(args, " "), dir, target, err, strings.TrimSpace(stderr.String()))
	}

	var packages []listedPackage
	stream := json.NewDecoder(bytes.NewReader(out))
	for {
		var pkg listedPackage
		switch err := stream.Decode(&pkg); {
		case errors.Is(err, io.EOF):
			return packages, nil
		case err != nil:
			return nil, fmt.Errorf("decoding go list output from %s: %w", dir, err)
		}
		packages = append(packages, pkg)
	}
}

// compiledInto maps one node of a `go list -test` graph back to the package
// whose source it is. -test invents three spellings around every package it
// augments — "p [p.test]" for p compiled with its own _test.go files, "p_test
// [p.test]" for the external test package, and "p.test" for the generated main
// — and all three are code under pkg/, so all three are roots of the search.
func compiledInto(node string) string {
	if open := strings.Index(node, " ["); open >= 0 {
		node = node[:open]
	}
	node = strings.TrimSuffix(node, ".test")
	return strings.TrimSuffix(node, "_test")
}

// dependencyClosure returns the packages `go list` resolves under pkg/ for one
// release target — as the node names the graph uses, tests included — and the
// import graph reachable from them.
//
// Every way of learning nothing is an error rather than an empty result. A
// pattern that matches no package, a graph with no nodes, or a published
// package the graph has no node for all produce a search that reports no
// violations, which is indistinguishable from a clean tree and is how a guard
// like this stops guarding: pkg/ is renamed, the pattern goes empty, and the
// suite stays green. A target is another way to learn nothing — the answer is
// only about the platform asked for — which is why the caller asks about all of
// them and every error below names the one it came from.
func dependencyClosure(dir string, target releaseTarget) (roots []string, graph map[string][]string, err error) {
	published, err := goList(dir, target, "./pkg/...")
	if err != nil {
		return nil, nil, err
	}
	if len(published) == 0 {
		return nil, nil, fmt.Errorf("go list ./pkg/... in %s for %s named no packages; "+
			"these guards only mean anything while that is where the published "+
			"packages live", dir, target)
	}

	names := make(map[string]bool, len(published))
	for _, pkg := range published {
		names[pkg.ImportPath] = true
	}

	// -deps for the closure, -test because a _test.go under pkg/ acquiring
	// go-git is the published package acquiring it in the one place nobody
	// reads as published surface.
	nodes, err := goList(dir, target, "-deps", "-test", "./pkg/...")
	if err != nil {
		return nil, nil, err
	}
	if len(nodes) == 0 {
		return nil, nil, fmt.Errorf("go list -deps -test ./pkg/... in %s for %s named no packages",
			dir, target)
	}

	graph = make(map[string][]string, len(nodes))
	for _, pkg := range nodes {
		graph[pkg.ImportPath] = pkg.Imports
	}

	covered := make(map[string]bool, len(names))
	roots = make([]string, 0, len(names))
	for node := range graph {
		if !names[compiledInto(node)] {
			continue
		}
		roots = append(roots, node)
		covered[compiledInto(node)] = true
	}
	for name := range names {
		if !covered[name] {
			return nil, nil, fmt.Errorf("the dependency graph for %s has no node for the "+
				"published package %s, so nothing was searched from it", target, name)
		}
	}
	slices.Sort(roots)

	return roots, graph, nil
}

// reaches walks graph breadth-first from roots and returns one shortest import
// chain per package satisfying forbidden, together with every node it was asked
// to follow and found no edges for.
//
// That second return is the fail-closed half. A node the graph does not
// describe is a subtree this walk did not search, and a search that did not
// happen must never read as a search that found nothing.
func reaches(roots []string, graph map[string][]string, forbidden func(string) bool) (chains [][]string, unresolved []string) {
	from := make(map[string]string, len(graph))
	seen := make(map[string]bool, len(graph))
	missing := map[string]bool{}

	queue := make([]string, 0, len(roots))
	for _, root := range roots {
		if seen[root] {
			continue
		}
		seen[root] = true
		queue = append(queue, root)
	}

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		if forbidden(node) {
			chains = append(chains, chainTo(node, from))
			// Not descended into. The chain to the first forbidden package is
			// the edge a reader has to remove; everything past it hangs off
			// that same edge and would only bury the finding in repetition.
			continue
		}

		imports, known := graph[node]
		if !known {
			missing[node] = true
			continue
		}
		for _, imported := range imports {
			// "C" is cgo's marker, not a package, and no node describes it.
			if imported == "C" || seen[imported] {
				continue
			}
			seen[imported] = true
			from[imported] = node
			queue = append(queue, imported)
		}
	}

	unresolved = make([]string, 0, len(missing))
	for node := range missing {
		unresolved = append(unresolved, node)
	}
	slices.Sort(unresolved)
	slices.SortFunc(chains, func(a, b []string) int {
		return strings.Compare(a[len(a)-1], b[len(b)-1])
	})

	return chains, unresolved
}

// chainTo reconstructs the route the search took to node, root first.
func chainTo(node string, from map[string]string) []string {
	chain := []string{node}
	for at, ok := from[node]; ok; at, ok = from[at] {
		chain = append(chain, at)
	}
	slices.Reverse(chain)

	return chain
}

// The invariant the direct-import guard states one edge of: nothing reachable
// from a published package is go-git, and nothing reachable from one is this
// package either.
//
// Both halves matter for the same reason. go-git reached at any depth is stock
// go-git downstream, because the replace directive that makes it faithful is
// this module's and stops here. This package reached at any depth is the same
// dependency wearing an internal path, and an internal wrapper between it and
// pkg/ changes nothing about what a downstream build resolves — it only moves
// the evidence out of the files the AST walk reads.
// Once per released target, because one target's answer is only about that
// target. Each runs as its own subtest so a failure names the platform in its
// own right rather than leaving a reader to infer it from a chain.
func TestNoPublishedPackageDependsOnGoGit(t *testing.T) {
	dir, module := moduleRoot(t)
	gitsign := module + "/internal/gitsign"

	for _, target := range releaseTargets {
		t.Run(target.String(), func(t *testing.T) {
			roots, graph, err := dependencyClosure(dir, target)
			if err != nil {
				t.Fatalf("resolving the dependency closure under pkg/ for %s: %v", target, err)
			}

			chains, unresolved := reaches(roots, graph, func(node string) bool {
				return namesGoGit(node) || compiledInto(node) == gitsign
			})
			if len(unresolved) > 0 {
				t.Fatalf("go list described no imports for %d package(s) reachable from pkg/ "+
					"when built for %s (%s); a graph this search could not finish walking is "+
					"not a graph it found clean",
					len(unresolved), target, strings.Join(unresolved, ", "))
			}

			for _, chain := range chains {
				t.Errorf("a published package reaches %s when the client is built for %s:\n\t%s\n"+
					"go-git is byte-faithful here only through the go.mod replace directive, "+
					"which a module depending on this one does not inherit, so anything under "+
					"pkg/ that can reach it — through an internal wrapper as much as directly, "+
					"on one release target as much as on all six — builds against stock go-git "+
					"downstream",
					chain[len(chain)-1], target, strings.Join(chain, "\n\t  -> "))
			}
		})
	}
}

// A stdlib edge for the fixture graphs below, so they branch the way a real
// closure does rather than running as a single chain.
const stdlibNode = "net/http"

// The bypass the direct-import guard cannot see, as a graph: pkg/client names
// nothing forbidden in its own import lines and reaches plumbing/object in
// three hops. The AST walk reads the first row of this table and stops.
func TestReachesFindsGoGitBehindAnInternalWrapper(t *testing.T) {
	const (
		published = "m/pkg/client"
		wrapper   = "m/internal/transport"
		rewriter  = "m/internal/rewrite"
		object    = goGitModule + "/plumbing/object"
	)
	graph := map[string][]string{
		published:  {stdlibNode, wrapper},
		wrapper:    {stdlibNode, rewriter},
		rewriter:   {object},
		object:     {"strings"},
		stdlibNode: {},
		"strings":  {},
	}

	// What the direct-import guard sees, spelled out: the published package's
	// own imports are clean, so the walk over pkg/ has nothing to report.
	for _, imported := range graph[published] {
		if namesGoGit(imported) {
			t.Fatalf("the fixture does not model the bypass: %s imports %s directly", published, imported)
		}
	}

	chains, unresolved := reaches([]string{published}, graph, namesGoGit)
	if len(unresolved) > 0 {
		t.Fatalf("the fixture graph left %s unresolved", strings.Join(unresolved, ", "))
	}
	if len(chains) != 1 {
		t.Fatalf("want one chain to go-git, got %d: %v", len(chains), chains)
	}

	want := []string{published, wrapper, rewriter, object}
	if !slices.Equal(chains[0], want) {
		t.Errorf("the reported chain is %v, want the shortest route %v", chains[0], want)
	}
}

// The test-augmented spellings `go list -test` invents are roots too, so a
// _test.go under pkg/ that reaches go-git is reported rather than skipped.
func TestReachesTreatsTestVariantsAsPublishedRoots(t *testing.T) {
	const (
		published = "m/pkg/client"
		external  = published + "_test [" + published + ".test]"
		object    = goGitModule + "/plumbing/object"
	)
	graph := map[string][]string{
		published:  {stdlibNode},
		external:   {published, object},
		object:     {},
		stdlibNode: {},
	}

	if compiledInto(external) != published {
		t.Fatalf("compiledInto(%q) = %q, want %q", external, compiledInto(external), published)
	}

	chains, unresolved := reaches([]string{published, external}, graph, namesGoGit)
	if len(unresolved) > 0 {
		t.Fatalf("the fixture graph left %s unresolved", strings.Join(unresolved, ", "))
	}
	if len(chains) != 1 || chains[0][len(chains[0])-1] != object {
		t.Errorf("the search did not reach %s through the external test package: %v", object, chains)
	}
}

// A graph missing the node an edge points at has to come back as unresolved,
// because the alternative is a silent "nothing found" from a subtree nobody
// looked at.
func TestReachesFailsClosedOnAnUnresolvedGraph(t *testing.T) {
	graph := map[string][]string{
		"m/pkg/client": {"m/internal/transport"},
	}

	chains, unresolved := reaches([]string{"m/pkg/client"}, graph, namesGoGit)
	if len(chains) != 0 {
		t.Errorf("the search reported %v from a graph it could not walk", chains)
	}
	if !slices.Equal(unresolved, []string{"m/internal/transport"}) {
		t.Errorf("unresolved = %v, want the node with no edges recorded", unresolved)
	}
}

// The bypass one platform at a time, as a module rather than as a graph
// literal: pkg/client imports an internal wrapper, and the wrapper's only
// go-git import is in a file the host's build constraints exclude. Every file
// under pkg/ is clean in every spelling, so the AST walk has nothing to read;
// the closure resolved for the host is clean too, which is what this guard used
// to be; and the release still ships two contaminated binaries.
//
// Stated as a mutant: narrow releaseTargets back to the host target — the
// single-pass `go list` this replaced — and the contaminated targets stop being
// resolved at all, so nothing reaches go-git and the fixture reports clean. The
// host assertion below is what makes that mutant fail here rather than pass
// quietly, because it pins the thing the old guard got right as the reason it
// was not enough.
func TestTheClosureFindsGoGitBehindAPlatformTaggedWrapper(t *testing.T) {
	host := hostTarget()

	contaminated := ""
	for _, target := range releaseTargets {
		if target.goos != host.goos {
			contaminated = target.goos
			break
		}
	}
	if contaminated == "" {
		t.Fatalf("releaseTargets (%v) names no GOOS besides the host's %q, so this fixture "+
			"cannot model a target the host's answer does not cover — which means the "+
			"closure is back to being resolved for one platform", releaseTargets, host.goos)
	}

	module := writePlatformTaggedFixture(t, contaminated)
	const (
		published = "fixture/pkg/client"
		wrapper   = "fixture/internal/wrap"
		object    = goGitModule + "/plumbing/object"
	)

	// The bypass itself, before the fix is given a chance to catch it: the
	// platform this test is running on sees a clean closure. If this ever fails,
	// the fixture has stopped modelling the hole and the rest proves nothing.
	roots, graph, err := dependencyClosure(module, host)
	if err != nil {
		t.Fatalf("resolving the fixture closure for the host (%s): %v", host, err)
	}
	if chains, _ := reaches(roots, graph, namesGoGit); len(chains) != 0 {
		t.Fatalf("the fixture does not model the bypass: the host target %s already "+
			"reaches go-git (%v), so a guard resolving one platform would have caught it",
			host, chains)
	}

	// And now every target the release builds, which is the fix.
	reached := 0
	for _, target := range releaseTargets {
		roots, graph, err := dependencyClosure(module, target)
		if err != nil {
			t.Fatalf("resolving the fixture closure for %s: %v", target, err)
		}
		chains, unresolved := reaches(roots, graph, namesGoGit)
		if len(unresolved) > 0 {
			t.Fatalf("the fixture graph for %s left %s unresolved",
				target, strings.Join(unresolved, ", "))
		}

		if target.goos != contaminated {
			if len(chains) != 0 {
				t.Errorf("%s reached %v, but the fixture hides go-git behind //go:build %s",
					target, chains, contaminated)
			}
			continue
		}

		reached++
		want := []string{published, wrapper, object}
		if len(chains) != 1 || !slices.Equal(chains[0], want) {
			t.Errorf("the closure for %s reported %v, want the one chain %v: the import is "+
				"in a file only %s compiles, and the failure has to name both the target "+
				"and the route", target, chains, want, contaminated)
		}
	}
	if reached == 0 {
		t.Errorf("no release target reached the go-git the fixture hides behind //go:build %s; "+
			"the closure is being resolved for platforms that cannot see it", contaminated)
	}
}

// writePlatformTaggedFixture builds a module whose published package reaches
// go-git only when compiled for goos, and returns its root.
//
// go-git is a local stub the fixture's go.mod replaces, so the fixture needs no
// network and no module cache — what is being tested is which files `go list`
// reads for which target, and a two-line package named
// github.com/go-git/go-git/v6 exercises that as well as the real one.
func writePlatformTaggedFixture(t *testing.T, goos string) string {
	t.Helper()

	root := t.TempDir()
	release := "go " + strings.TrimPrefix(runtime.Version(), "go") + "\n"
	stub, module := filepath.Join(root, "gogit"), filepath.Join(root, "module")

	files := map[string]string{
		filepath.Join(stub, "go.mod"):                                 "module " + goGitModule + "\n\n" + release,
		filepath.Join(stub, "plumbing", "object", "object.go"):        "package object\n\ntype Commit struct{}\n",
		filepath.Join(module, "go.mod"):                               "module fixture\n\n" + release + "\nrequire " + goGitModule + " v6.0.0\n\nreplace " + goGitModule + " => ../gogit\n",
		filepath.Join(module, "pkg", "client", "client.go"):           "package client\n\nimport \"fixture/internal/wrap\"\n\ntype Commit = wrap.Commit\n",
		filepath.Join(module, "internal", "wrap", "wrap_"+goos+".go"): "//go:build " + goos + "\n\npackage wrap\n\nimport \"" + goGitModule + "/plumbing/object\"\n\ntype Commit = object.Commit\n",
		filepath.Join(module, "internal", "wrap", "wrap_portable.go"): "//go:build !" + goos + "\n\npackage wrap\n\ntype Commit struct{}\n",
	}
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("building the fixture tree: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
	}

	return module
}

// And the same for a tree with nothing published in it: the closure has to
// refuse rather than hand back an empty root set that every predicate passes.
//
// The fixture has to contain a pkg/ directory holding no Go files, because
// that is the only shape that reaches the assertion. A module with no pkg/ at
// all makes `go list ./pkg/...` exit non-zero ("lstat ./pkg/: no such file or
// directory"), so the closure returns from goList's error path and the
// empty-pattern guard is never consulted -- a fixture built that way passes
// with the guard deleted, which is the exact accounting this file rejects
// everywhere else. `go list` exits 0 and merely warns when the pattern
// resolves and matches nothing, and that is the case the guard is for: pkg/
// still there, emptied by a move that nobody pointed these tests at.
//
// Stated as a mutant: delete both `named no packages` guards and
// dependencyClosure returns an empty root set and a nil error -- the silently
// clean answer they exist to prevent. Against a fixture with no pkg/ at all
// that mutant survives; against this one it does not.
func TestDependencyClosureRefusesATreeWithNoPublishedPackages(t *testing.T) {
	module := writeFixtureModule(t)
	if err := os.MkdirAll(filepath.Join(module, "pkg"), 0o750); err != nil {
		t.Fatalf("building the fixture pkg/ tree: %v", err)
	}

	roots, graph, err := dependencyClosure(module, hostTarget())
	if err == nil {
		t.Fatalf("a pkg/ with no packages in it resolved to %d root(s) and %d node(s) "+
			"instead of an error", len(roots), len(graph))
	}
}

// The other half of the same shape, kept apart from it: a module with no pkg/
// directory at all cannot resolve the pattern, and that has to surface as the
// `go list` failure it is rather than as a clean empty tree.
func TestDependencyClosureRefusesATreeWithNoPublishedDirectory(t *testing.T) {
	roots, graph, err := dependencyClosure(writeFixtureModule(t), hostTarget())
	if err == nil {
		t.Fatalf("a module with no pkg/ resolved to %d root(s) and %d node(s) instead of an error",
			len(roots), len(graph))
	}
}

// writeFixtureModule returns a temporary directory holding nothing but a go.mod
// naming the toolchain running these tests, so `go list` resolves in it.
func writeFixtureModule(t *testing.T) string {
	t.Helper()

	module := t.TempDir()
	manifest := "module fixture\n\ngo " + strings.TrimPrefix(runtime.Version(), "go") + "\n"
	if err := os.WriteFile(filepath.Join(module, "go.mod"), []byte(manifest), 0o600); err != nil {
		t.Fatalf("writing the fixture go.mod: %v", err)
	}

	return module
}
