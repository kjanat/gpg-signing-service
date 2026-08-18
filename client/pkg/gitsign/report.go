package gitsign

import "strings"

// reportEmptyRange explains a base..HEAD that selected no commits. Each cause
// has a different remedy, and "nothing happened" on its own sends the operator
// looking in the wrong place.
func (s *session) reportEmptyRange(base, head string) {
	switch {
	case base != head:
		s.warn("No commits in %s..HEAD; nothing was signed. Check that base is an ancestor "+
			"of HEAD on the branch you selected.", base)
	case s.opts.Base != "":
		s.warn("base=%s resolved to %s, which is HEAD itself; base is an exclusive lower bound, "+
			"so the range is empty — pass the commit before the first one you want signed.",
			s.opts.Base, base)
	case s.result.Branch == s.opts.DefaultBranch:
		s.printf("Nothing to sign; HEAD (%s) is already signed and verified.", base)
	default:
		s.printf("Nothing to sign; %s adds no commits on top of origin/%s (%s).",
			s.result.Branch, s.opts.DefaultBranch, base)
	}
}

// reportNothingStale explains a range whose commits all already verify.
func (s *session) reportNothingStale(w *workset, base string) {
	others := 0
	for commit := range w.raw {
		if !w.mine[commit] {
			others++
		}
	}

	if others == len(w.raw) && !s.opts.SignOthers {
		s.warn("Nothing was signed: all %d commit(s) in %s..HEAD were committed by identities "+
			"the key does not carry — re-run with --sign-others (dispatch with sign_others from CI) "+
			"to include them.", others, base)
		return
	}
	s.printf("Nothing to sign in %s..HEAD (%d commit(s) by others).", base, others)
}

// reportDropped warns about signatures the rewrite destroyed without replacing.
// This is an explicit warning rather than a log line because the run just
// removed attestations it cannot recreate, and the log scrolls past.
func (s *session) reportDropped() {
	var dropped []string
	for _, rewrite := range s.result.Rewrites {
		if rewrite.Mark == MarkStripped {
			dropped = append(dropped, short(rewrite.Commit))
		}
	}
	if len(dropped) == 0 {
		return
	}

	s.warn("Dropped the signature on %d commit(s) (%s); they were committed by identities the key "+
		"does not carry, so the rewrite stripped each signature and nothing replaced it — re-run with "+
		"--sign-others (dispatch with sign_others from CI) to sign them instead.",
		len(dropped), strings.Join(dropped, ", "))
}
