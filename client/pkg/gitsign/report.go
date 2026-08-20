package gitsign

import (
	"slices"
	"strings"
)

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

// reportStaleMergetag warns that a merge commit's mergetag header now names a
// commit that no longer exists under that SHA.
//
// A mergetag embeds the whole tag object, including its own signature over its
// own "object <sha>" line. Repointing it at the rewritten commit would break
// the tagger's signature, and this run has no key to re-make it with, so the
// header is left alone. Nothing is corrupt — git fsck stays clean — but
// "git log --show-signature" on the rewritten merge describes a merged tag that
// matches none of its parents.
// A merge is rewritten as soon as any one parent moves, and the embedded tag
// names one specific parent, so moved is consulted rather than assumed: a merge
// whose first parent moved while the tagged one stayed put carries a mergetag
// that is still accurate, and saying otherwise sends the operator looking for
// damage that is not there.
func (s *session) reportStaleMergetag(raw []byte, commit string, moved map[string]bool) {
	merge, err := decodeCommit(raw)
	if err != nil || merge.MergeTag == "" {
		return
	}

	// An octopus merge of several signed tags concatenates their bodies into
	// the one field, so every moved parent is checked against it rather than
	// only the first "object" line.
	var stale []string
	for parent := range moved {
		if strings.Contains(merge.MergeTag, "object "+parent) {
			stale = append(stale, short(parent))
		}
	}
	if len(stale) == 0 {
		return
	}
	slices.Sort(stale)

	s.warn("the merge %s carries a mergetag naming %s, which this run rewrote; the embedded tag is "+
		"signed by its tagger, so it cannot be repointed at the rewritten parent and now matches no parent.",
		short(commit), strings.Join(stale, ", "))
}
