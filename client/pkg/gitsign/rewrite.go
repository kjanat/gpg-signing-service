package gitsign

import (
	"context"
	"fmt"
	"strings"
)

// workset holds the per-commit facts the rewrite decisions are made from.
type workset struct {
	raw      map[string][]byte
	mine     map[string]bool
	ours     map[string]bool
	signed   map[string]bool
	verified map[string]bool
	detail   map[string]string
	// checked marks the commits verification actually ran on. A commit that was
	// never checked is unverified for a different reason than one that failed.
	checked map[string]bool
	stale   map[string]bool
}

// classify reads every commit in the range and works out which ones need to be
// rewritten.
func (s *session) classify(ctx context.Context, commits []string) (*workset, error) {
	w := &workset{
		raw:      make(map[string][]byte, len(commits)),
		mine:     make(map[string]bool, len(commits)),
		ours:     make(map[string]bool, len(commits)),
		signed:   make(map[string]bool, len(commits)),
		verified: make(map[string]bool, len(commits)),
		detail:   make(map[string]string),
		checked:  make(map[string]bool),
		stale:    make(map[string]bool),
	}

	for _, commit := range commits {
		raw, err := s.repo.catFileCommit(ctx, commit)
		if err != nil {
			return nil, err
		}
		w.raw[commit] = raw

		email, err := committerEmail(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", commit, err)
		}
		w.mine[commit] = email != "" && s.identities[email]
		w.ours[commit] = s.opts.SignOthers || w.mine[commit]

		signed, err := isSigned(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", commit, err)
		}
		w.signed[commit] = signed

		if w.ours[commit] && signed {
			good, detail := s.key.verify(raw)
			w.verified[commit] = good
			w.detail[commit] = detail
			w.checked[commit] = true
		}
	}

	// rev-list --reverse --topo-order hands back parents before children, so a
	// single forward pass propagates staleness down the whole range.
	for _, commit := range commits {
		parents, err := parentsOf(w.raw[commit])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", commit, err)
		}
		moved := false
		for _, parent := range parents {
			if w.stale[parent] {
				moved = true
				break
			}
		}
		if moved || (w.ours[commit] && !w.verified[commit]) {
			w.stale[commit] = true
		}
	}

	return w, nil
}

// guard refuses a run that would rewrite commits already carrying a signature,
// unless the operator asked for it. Rewriting them destroys signatures that may
// not be this service's to replace.
func (s *session) guard(w *workset, commits []string) error {
	if s.opts.AllowResign {
		return nil
	}

	var resign, report []string
	for _, commit := range commits {
		if !w.stale[commit] || !w.signed[commit] {
			continue
		}
		resign = append(resign, commit)

		reason := "a rewritten parent invalidates its signature"
		if w.checked[commit] && !w.verified[commit] {
			// The detail is already the explanation; an unrecognized
			// failure carries the library's own words rather than being
			// flattened into "did not verify".
			reason = w.detail[commit]
		}
		// A commit the key does not cover is reparented, not re-signed: the
		// rewrite strips its signature and nothing replaces it.
		action := "drop the signature on"
		if w.ours[commit] {
			action = "re-sign"
		}
		report = append(report, fmt.Sprintf("  would %s %s (%s)", action, short(commit), reason))
	}

	if len(resign) == 0 {
		return nil
	}
	for _, line := range report {
		s.printf("%s", line)
	}
	return &ResignError{Stale: len(w.stale), Resign: resign, Report: report}
}

// rewrite rebuilds every stale commit and moves HEAD to the new tip.
func (s *session) rewrite(ctx context.Context, w *workset, commits []string, base, head string) error {
	rewritten := make(map[string]string, len(w.stale))

	for _, commit := range commits {
		if !w.stale[commit] {
			continue
		}

		body, mark, err := s.rebuild(ctx, w, commit, rewritten)
		if err != nil {
			return err
		}

		newSHA, err := s.repo.hashObject(ctx, body)
		if err != nil {
			return err
		}
		if mark == MarkSigned {
			if good, detail := s.verifyWritten(ctx, newSHA); !good {
				return fmt.Errorf("%s did not verify after signing: %s", newSHA, detail)
			}
			s.result.Signed++
		}

		rewritten[commit] = newSHA
		s.result.Rewrites = append(s.result.Rewrites, Rewrite{Commit: commit, NewCommit: newSHA, Mark: mark})
		s.printf("  %-8s %s -> %s", mark, short(commit), short(newSHA))
	}

	s.printf("Signed %d of %d commit(s) in %s..HEAD", s.result.Signed, len(commits), base)
	s.reportDropped()

	tip := head
	if replacement, ok := rewritten[head]; ok {
		tip = replacement
	}
	if good, detail := s.verifyWritten(ctx, tip); !good {
		// The cause decides the advice. A tip left unsigned is the one the
		// operator can fix with a flag; a mismatch or an expired key is not.
		remedy := ""
		if detail == reasonUnsigned {
			remedy = " — its committer is an identity the key does not carry, so re-run with " +
				"--sign-others (dispatch with sign_others from CI) to include it"
		}
		s.warn("Signed %d commit(s), but the tip %s carries no signature this key can verify (%s)%s.",
			s.result.Signed, short(tip), detail, remedy)
	}

	if err := s.repo.updateRef(ctx, tip, head); err != nil {
		return fmt.Errorf("HEAD moved while the run was signing, so the rewrite was not applied; "+
			"the new objects are unreferenced and the branch is untouched: %w", err)
	}
	s.result.Tip = tip
	s.result.RefUpdated = true
	s.printf("HEAD now points at %s. Nothing was pushed; publishing this rewrite needs a force push.", short(tip))
	return nil
}

// rebuild produces the new object body for one stale commit.
func (s *session) rebuild(ctx context.Context, w *workset, commit string, rewritten map[string]string) ([]byte, Mark, error) {
	parents, err := parentsOf(w.raw[commit])
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", commit, err)
	}
	// Merge commits carry several parents, and each one is remapped
	// independently: only some of a merge's ancestry may have been rewritten.
	remapped := make([]string, len(parents))
	moved := make(map[string]bool)
	for index, parent := range parents {
		remapped[index] = parent
		if replacement, ok := rewritten[parent]; ok {
			remapped[index] = replacement
			moved[parent] = true
		}
	}
	if len(moved) > 0 {
		s.reportStaleMergetag(w.raw[commit], commit, moved)
	}

	payload, err := unsignedObject(w.raw[commit], remapped)
	if err != nil {
		return nil, "", fmt.Errorf("%s: %w", commit, err)
	}
	if !w.ours[commit] {
		// "reparent" reads identically for a commit that never carried a
		// signature, so name the destructive case separately.
		if w.signed[commit] {
			return payload, MarkStripped, nil
		}
		return payload, MarkReparent, nil
	}

	signature, err := s.requestSignature(ctx, payload)
	if err != nil {
		return nil, "", err
	}
	return withSignature(payload, signature), MarkSigned, nil
}

// requestSignature asks the service to sign the rebuilt commit bytes.
func (s *session) requestSignature(ctx context.Context, payload []byte) ([]byte, error) {
	result, err := s.signer.Sign(ctx, string(payload), s.opts.KeyID)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	if !strings.Contains(result.Signature, pgpArmorMarker) {
		return nil, fmt.Errorf("the signing service returned no PGP signature: %q", result.Signature)
	}
	return []byte(strings.Trim(result.Signature, "\n")), nil
}

// verifyWritten reads an object back out of the repository and checks it
// against the service key. Reading it back rather than checking the bytes in
// hand is the point: it proves git stored what this run built.
func (s *session) verifyWritten(ctx context.Context, sha string) (bool, string) {
	raw, err := s.repo.catFileCommit(ctx, sha)
	if err != nil {
		return false, err.Error()
	}
	return s.key.verify(raw)
}
