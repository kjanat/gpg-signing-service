package client

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"testing"

	"github.com/kjanat/gpg-signing-service/client/pkg/api"
)

// TestErrorCodesExistOnTheWire is the reverse of the server's drift test.
//
// src/__tests__/error-docs.test.ts walks the service's enum and fails a code
// with no documentation section. Nothing walked the other way, so this package
// could — and did — export a constant naming a code the service has never
// emitted: ErrCodeDegraded sat here through a release with no member in
// ErrorCodeSchema, no handler, and no section in docs/errors.md, which made
// `GET /e/SERVICE_DEGRADED` a 404 for anyone who found the constant and
// branched on it.
//
// Checked against the spec embedded in pkg/api rather than a hand-copied list:
// that blob is generated from the same document the Hono app publishes, and
// TestEmbeddedSpecMatchesSource keeps it current. So a constant that survives
// this test is a code the service really declares.
//
// The constants are read out of errors.go rather than listed here. They were
// listed here, which made the guarantee weaker in one direction than the
// server's: that one walks ERROR_CODES and cannot miss a member, while a tenth
// ErrCode constant added without a tenth line in a map passed silently. Parsing
// the declaration is what makes "every exported code constant" mean it.
func TestErrorCodesExistOnTheWire(t *testing.T) {
	codes := exportedErrorCodes(t)

	// A guard on the guard: a rename that stopped matching the prefix would
	// otherwise leave this looping over nothing and reporting success.
	if len(codes) < 8 {
		t.Fatalf("found only %d ErrCode constants in errors.go; the source scan is not finding them", len(codes))
	}

	for name, code := range codes {
		if !api.ErrorCode(code).Valid() {
			t.Errorf("%s = %q is not a member of the service's ErrorCode enum; either the service stopped "+
				"declaring it or the constant was invented here", name, code)
		}
	}
}

// exportedErrorCodes returns every `ErrCode…` string constant declared in
// errors.go, keyed by its Go name.
//
// Source-parsed rather than reflected: Go has no runtime enumeration of a
// package's constants, and the whole point is to catch a constant nobody
// remembered to add to a list.
func exportedErrorCodes(t *testing.T) map[string]string {
	t.Helper()

	file, err := parser.ParseFile(token.NewFileSet(), "errors.go", nil, 0)
	if err != nil {
		t.Fatalf("parsing errors.go: %v", err)
	}

	codes := map[string]string{}
	for _, decl := range file.Decls {
		genDecl, ok := decl.(*ast.GenDecl)
		if !ok || genDecl.Tok != token.CONST {
			continue
		}
		for _, spec := range genDecl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range valueSpec.Names {
				if !ast.IsExported(name.Name) || len(name.Name) < 8 || name.Name[:7] != "ErrCode" {
					continue
				}
				if i >= len(valueSpec.Values) {
					continue
				}
				lit, ok := valueSpec.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				value, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s: %v", name.Name, err)
				}
				codes[name.Name] = value
			}
		}
	}
	return codes
}
