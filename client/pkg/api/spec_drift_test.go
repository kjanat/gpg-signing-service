package api

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// normalizeGeneratorRewrites undoes the three edits oapi-codegen and
// kin-openapi make to a spec on the way into the embedded blob, so that a
// comparison against the source document is a comparison of contracts rather
// than of the generator's serialization habits.
//
// Applied to *both* documents, so each rewrite costs the test only its own
// field: an `operationId` is never written by the Hono app, and the values
// codegen derives for it come from the method and path, which are compared.
// Deliberately targeted rather than a general "drop empty and false" sweep —
// such a sweep would also erase `security: [{"bearerAuth": []}]`, where the
// empty array is the scope list and its disappearance would be real drift.
//
// A rewrite this does not know about surfaces as a test failure, not as a
// silent pass.
func normalizeGeneratorRewrites(doc map[string]any) {
	// kin-openapi marshals an empty component map away entirely.
	if components, ok := doc["components"].(map[string]any); ok {
		for key, value := range components {
			if sub, ok := value.(map[string]any); ok && len(sub) == 0 {
				delete(components, key)
			}
		}
	}

	paths, _ := doc["paths"].(map[string]any)
	for _, item := range paths {
		operations, ok := item.(map[string]any)
		if !ok {
			continue
		}
		for _, value := range operations {
			operation, ok := value.(map[string]any)
			if !ok {
				continue
			}
			// Synthesized by codegen when the source omits it, which the Hono
			// app always does.
			delete(operation, "operationId")

			parameters, _ := operation["parameters"].([]any)
			for _, entry := range parameters {
				parameter, ok := entry.(map[string]any)
				if !ok {
					continue
				}
				// `omitempty` on kin-openapi's Parameter.Required.
				if required, ok := parameter["required"].(bool); ok && !required {
					delete(parameter, "required")
				}
			}
		}
	}
}

// TestEmbeddedSpecMatchesSource guards the second half of the generated-artifact
// chain. A sibling TypeScript test (src/__tests__/openapi-spec.test.ts) checks
// that client/openapi.json is what the Hono app produces; this one checks that
// api.gen.go was generated from that same openapi.json.
//
// Without it, running only the first half of `task generate:api` — or resolving
// a merge conflict in openapi.json by hand — leaves a client whose types, method
// set and embedded spec describe an older contract, and every other test still
// passes, because the code compiles and the spec parses.
//
// The embedded spec is the right proxy for the whole file: oapi-codegen writes
// it from the same in-memory document it generates the types from, so an
// embedded copy that is current means types that are current.
func TestEmbeddedSpecMatchesSource(t *testing.T) {
	const sourcePath = "../../openapi.json"

	sourceBytes, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read %s: %v", sourcePath, err)
	}
	embeddedBytes, err := GetSpecJSON()
	if err != nil {
		t.Fatalf("decode embedded spec: %v", err)
	}

	// Compared as parsed documents rather than bytes: codegen re-serializes the
	// spec into the blob, so key order and spacing are its choice, not drift.
	var source, embedded map[string]any
	if err := json.Unmarshal(sourceBytes, &source); err != nil {
		t.Fatalf("parse %s: %v", sourcePath, err)
	}
	if err := json.Unmarshal(embeddedBytes, &embedded); err != nil {
		t.Fatalf("parse embedded spec: %v", err)
	}
	normalizeGeneratorRewrites(source)
	normalizeGeneratorRewrites(embedded)

	if !reflect.DeepEqual(source, embedded) {
		t.Errorf("pkg/api/api.gen.go was generated from a different %s than the one committed; "+
			"run `task generate:api` and commit the result", sourcePath)
	}
}
