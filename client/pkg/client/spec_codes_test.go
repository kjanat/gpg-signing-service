package client

import (
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
func TestErrorCodesExistOnTheWire(t *testing.T) {
	codes := map[string]string{
		"ErrCodeAuthMissing":          ErrCodeAuthMissing,
		"ErrCodeAuthInvalid":          ErrCodeAuthInvalid,
		"ErrCodeAuthSubjectUntrusted": ErrCodeAuthSubjectUntrusted,
		"ErrCodeDegraded":             ErrCodeDegraded,
		"ErrCodeKeyNotFound":          ErrCodeKeyNotFound,
		"ErrCodeKeyNotAllowed":        ErrCodeKeyNotAllowed,
		"ErrCodeInvalidRequest":       ErrCodeInvalidRequest,
		"ErrCodeInternalError":        ErrCodeInternalError,
	}

	for name, code := range codes {
		if !api.ErrorCode(code).Valid() {
			t.Errorf("%s = %q is not a member of the service's ErrorCode enum; either the service stopped "+
				"declaring it or the constant was invented here", name, code)
		}
	}
}
