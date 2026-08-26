package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/kjanat/gpg-signing-service/client/pkg/client"
)

// reportFailure prints the actionable half of an error underneath cobra's own
// one-line `Error:`.
//
// The service answers a refusal with four separate things — what happened, the
// subject it was about, what to change, and where to read more — and until now
// a caller saw whichever of them survived being formatted into a single error
// string, or, for anything driving the API directly, the raw JSON envelope
// dumped into the log. Both are unreadable in the place they are actually read:
// a CI log that wrapped at the terminal width, with the interesting sentence
// somewhere in the middle of a `{"error":"…","code":"…","requestId":"…"}` blob.
//
// So the fields go one per line, labelled and aligned. The cost is a few lines
// of output on a failure that already ended the job; the benefit is that the
// next action is legible without opening a JSON formatter.
//
// Silent when the error carries none of them, which covers every locally
// constructed error and any service older than the release that added the
// fields — so this never prints an empty frame around nothing.
func reportFailure(w io.Writer, err error) {
	// Guidance and the request id are gathered before either is tested, because
	// either one alone is worth printing. Gating the whole block on guidance
	// dropped the id for every refusal that carried no hint — an intermediary's
	// 429, a deployment older than the release that added the fields — which is
	// exactly the failure docs/troubleshooting.md asks the operator to quote an
	// id for.
	guidance, _ := client.GuidanceFor(err)
	requestID := requestIDOf(err)
	if guidance == (client.Guidance{}) && requestID == "" {
		return
	}

	// Aligned on the longest label rather than a tab, because the width of a tab
	// depends on the viewer and GitHub's log renderer is not the one the author
	// tested in.
	write := func(label, value string) {
		if value == "" {
			return
		}
		// Nothing useful to do if the failure report itself cannot be written:
		// the process is already on its way out with a non-zero status, and a
		// second error about the first one helps nobody.
		_, _ = fmt.Fprintf(w, "  %-8s %s\n", label+":", value)
	}

	write("subject", guidance.Subject)
	// Hints are a sentence or two. Wrapping is left to the terminal; what matters
	// is that the hint starts on its own line rather than in the middle of one.
	write("hint", strings.TrimSpace(guidance.Hint))
	write("docs", guidance.Docs)
	// The id is on the error types rather than in Guidance — it identifies the
	// request, it does not advise — but it belongs in the same block: it is what
	// an operator quotes when the hint was not enough.
	write("request", requestID)
}

// requestIDOf digs out the server's request identifier, whichever refusal type
// is carrying it.
//
// A 429 is the one whose id lives only in the echoed X-Request-ID header —
// RateLimitErrorSchema declares no `requestId` — so it is read from the error
// rather than from an envelope field that does not exist.
func requestIDOf(err error) string {
	var authErr *client.AuthError
	var rateErr *client.RateLimitError
	var svcErr *client.ServiceError
	switch {
	case errors.As(err, &authErr):
		return authErr.RequestID
	case errors.As(err, &rateErr):
		return rateErr.RequestID
	case errors.As(err, &svcErr):
		return svcErr.RequestID
	}
	return ""
}
