package gitsign

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

// RepairOptions configures a [Repair] run.
//
// Every bound is explicit. This command rewrites the identity a commit claims,
// which is the one field a signature is supposed to make unforgeable, so
// nothing about the range, the tip, the identity being written or the
// identities being replaced is inferred from the repository.
type RepairOptions struct {
	// Dir is the working tree to operate on; empty means the current directory.
	Dir string
	// Base is the exclusive lower bound of the range. Required.
	Base string
	// ExpectedTip is the commit the range must currently end at, and the commit
	// HEAD must currently point at. Required.
	ExpectedTip string
	// Identity is the "Name <address>" both identity headers are rewritten to.
	// Required.
	Identity string
	// ExpectIdentities are the addresses the range's existing author and
	// committer headers are allowed to carry. At least one is required; the
	// target identity's own address is always allowed on top of them.
	ExpectIdentities []string
	// KeyID selects the signing key; empty uses the service default.
	KeyID string
	// DryRun validates the range and prints the plan without asking the service
	// for a signature or writing an object.
	DryRun bool
	// Out receives progress output; nil discards it.
	Out io.Writer
}

// RepairMapping is one commit's old-SHA -> new-SHA outcome, alongside the
// identity it used to claim. The old identity is part of the record on
// purpose: the mapping is the audit trail for a rewrite that changed who
// history says wrote these commits.
type RepairMapping struct {
	Commit    string `json:"commit"`
	NewCommit string `json:"newCommit,omitempty"`
	Tree      string `json:"tree"`
	Author    string `json:"author"`
	Committer string `json:"committer"`
}

// RepairResult summarizes a repair run.
type RepairResult struct {
	Base        string `json:"base"`
	ExpectedTip string `json:"expectedTip"`
	// Tip is the repaired tip the caller should publish. It is empty on a dry
	// run, so a caller that pushes whatever this field holds cannot publish a
	// plan.
	Tip      string `json:"tip,omitempty"`
	Tree     string `json:"tree"`
	Identity string `json:"identity"`
	DryRun   bool   `json:"dryRun"`
	Scanned  int    `json:"commitsScanned"`
	Repaired int    `json:"commitsRepaired"`

	Mapping  []RepairMapping `json:"mapping"`
	Warnings []string        `json:"warnings,omitempty"`

	// RefUpdated and Pushed are always false. They are reported rather than
	// omitted so a caller reading this document next to a sign-commit one does
	// not have to know which commands can move a ref to find out that this one
	// did not.
	RefUpdated bool `json:"refUpdated"`
	Pushed     bool `json:"pushed"`
}

// Repair rebuilds every commit in base..expected-tip so that it claims one
// identity, is signed by the service key, and keeps everything else git
// recorded.
//
// It is a deliberately dangerous operation and it is separate from [Run] for
// that reason. Run corrects a missing attestation; this rewrites the author and
// committer headers themselves, which is a claim about who wrote the code. It
// exists for one failure: a merge path that manufactured commits under an
// identity that never wrote them, leaving history that cannot be signed
// truthfully without being rebuilt.
//
// It writes objects and nothing else. No ref is moved, nothing is pushed, and
// the repaired tip is handed back for a caller that has already checked it to
// publish under its own force-with-lease. The blast radius of publishing a
// rewritten branch is not a decision this package can make.
//
// Every guarantee is asserted against the objects git stored rather than the
// bytes this run built: each rewritten commit is read back and checked for the
// target identity, the original timestamps, the original tree, the original
// message, the remapped parents, and a signature the service key verifies. The
// run fails closed on the first one that does not hold, leaving the objects it
// wrote unreferenced and every ref untouched.
func Repair(ctx context.Context, signer Signer, opts RepairOptions) (*RepairResult, error) {
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	target, allowed, err := repairBounds(opts)
	if err != nil {
		return nil, err
	}

	r := &repairer{
		repo:    &repo{dir: opts.Dir},
		signer:  signer,
		opts:    opts,
		target:  target,
		allowed: allowed,
		result: &RepairResult{
			Identity: target.String(),
			DryRun:   opts.DryRun,
		},
	}

	name, err := r.repo.objectFormat(ctx)
	if err != nil {
		return nil, err
	}
	if r.format, err = parseObjectFormat(name); err != nil {
		return nil, err
	}

	armored, err := signer.PublicKey(ctx, opts.KeyID)
	if err != nil {
		return nil, fmt.Errorf("could not fetch the public key: %w", err)
	}
	if r.key, err = newSigningKey(armored); err != nil {
		return nil, err
	}
	if err := r.warnCompatObjectFormat(ctx); err != nil {
		return nil, err
	}

	if err := r.run(ctx); err != nil {
		return r.result, err
	}
	return r.result, nil
}

// repairBounds validates the options that have no safe default.
func repairBounds(opts RepairOptions) (Identity, map[string]bool, error) {
	if strings.TrimSpace(opts.Base) == "" {
		return Identity{}, nil, errors.New("base is required: repair-history rewrites an explicit range, " +
			"so the exclusive lower bound has to be named rather than resolved")
	}
	if strings.TrimSpace(opts.ExpectedTip) == "" {
		return Identity{}, nil, errors.New("expected-tip is required: the run refuses to start unless the " +
			"history it was asked to repair is still the history that is there")
	}
	target, err := ParseIdentity(opts.Identity)
	if err != nil {
		return Identity{}, nil, err
	}
	if len(opts.ExpectIdentities) == 0 {
		return Identity{}, nil, errors.New("at least one expect-identity is required: the run will only " +
			"rewrite identities it was told to expect, so a commit by anyone else stops it instead of " +
			"being quietly reattributed")
	}

	// The target's own address is always allowed. Without it a repair could
	// never be re-run over a range it had already half-corrected, and the
	// correct identity is by definition not a surprise.
	allowed := map[string]bool{strings.ToLower(target.Email): true}
	for _, address := range opts.ExpectIdentities {
		address = strings.ToLower(strings.TrimSpace(address))
		if address == "" {
			return Identity{}, nil, errors.New("expect-identity must be an email address, got an empty value")
		}
		allowed[address] = true
	}
	return target, allowed, nil
}

// repairer carries the state of one repair run.
type repairer struct {
	repo    *repo
	signer  Signer
	opts    RepairOptions
	key     *signingKey
	format  objectFormat
	target  Identity
	allowed map[string]bool
	result  *RepairResult
}

func (r *repairer) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(r.opts.Out, format+"\n", args...)
}

func (r *repairer) warn(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	r.result.Warnings = append(r.result.Warnings, message)
	_, _ = fmt.Fprintf(r.opts.Out, "warning: %s\n", message)
}

func (r *repairer) run(ctx context.Context) error {
	commits, err := r.selectRange(ctx)
	if err != nil {
		return err
	}

	plan, err := r.plan(ctx, commits)
	if err != nil {
		return err
	}
	if r.opts.DryRun {
		r.printf("Dry run: nothing was signed and no object was written. "+
			"%d commit(s) would be rebuilt as %s.", len(commits), r.target)
		return nil
	}
	return r.apply(ctx, plan)
}

// selectRange resolves the bounds, refuses a history that moved, and returns
// the commits oldest-to-newest.
func (r *repairer) selectRange(ctx context.Context) ([]string, error) {
	base, err := r.repo.resolveCommit(ctx, r.opts.Base)
	if err != nil {
		return nil, err
	}
	tip, err := r.repo.resolveCommit(ctx, r.opts.ExpectedTip)
	if err != nil {
		return nil, err
	}
	r.result.Base = base
	r.result.ExpectedTip = tip

	// HEAD is checked as well as the named tip, because the caller's next step
	// is a force-with-lease from the ref this checkout is on. A run against a
	// tip that HEAD does not hold would hand back a repaired chain built from
	// commits the push is not replacing.
	head, err := r.repo.head(ctx)
	if err != nil {
		return nil, err
	}
	if head != tip {
		return nil, fmt.Errorf("history moved: expected-tip resolves to %s but HEAD is at %s; "+
			"re-read the branch and re-run with the tip that is actually there", tip, head)
	}

	commits, err := r.repo.revList(ctx, base, tip)
	if err != nil {
		return nil, err
	}
	if len(commits) == 0 {
		return nil, fmt.Errorf("no commits in %s..%s; base is an exclusive lower bound, so it must be an "+
			"ancestor of the tip and not the tip itself", base, tip)
	}
	// rev-list --reverse --topo-order emits parents before children and every
	// other commit in the range is an ancestor of the tip, so the tip is last.
	// If it is not, the range is not the one the caller described.
	if last := commits[len(commits)-1]; last != tip {
		return nil, fmt.Errorf("the range %s..%s ends at %s rather than the expected tip %s", base, tip, last, tip)
	}
	r.result.Scanned = len(commits)

	tree, err := r.repo.treeOf(ctx, tip)
	if err != nil {
		return nil, err
	}
	r.result.Tree = tree
	return commits, nil
}

// repairStep is one validated commit, ready to be rebuilt.
type repairStep struct {
	commit    string
	raw       []byte
	tree      string
	message   []byte
	parents   []string
	author    ident
	committer ident
}

// plan reads and validates every commit in the range before anything is
// signed or written.
//
// Validation is a pass of its own so that a range holding one commit this
// command refuses costs nothing: no signature is requested, no object is
// written, and the operator sees every offending commit at once rather than
// discovering them one failed run at a time.
func (r *repairer) plan(ctx context.Context, commits []string) ([]repairStep, error) {
	steps := make([]repairStep, 0, len(commits))
	var unexpected []string

	for _, commit := range commits {
		raw, err := r.repo.catFileCommit(ctx, commit)
		if err != nil {
			return nil, err
		}
		// Decoding is not used to rebuild anything — every edit below is at the
		// byte level — but a commit go-git cannot parse is one whose shape this
		// run has not understood, and that is a reason to stop.
		if _, err := decodeCommit(raw); err != nil {
			return nil, fmt.Errorf("%s: %w", commit, err)
		}

		author, committer, err := readIdents(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", commit, err)
		}
		for header, who := range map[string]ident{authorHeader: author, committerHeader: committer} {
			if !r.allowed[strings.ToLower(who.email)] {
				unexpected = append(unexpected, fmt.Sprintf("  %s %s %s", short(commit), header, who.display()))
			}
		}

		tree, err := treeHeader(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", commit, err)
		}
		message, err := messageBody(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", commit, err)
		}
		parents, err := parentsOf(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", commit, err)
		}

		steps = append(steps, repairStep{
			commit: commit, raw: raw, tree: tree, message: message,
			parents: parents, author: author, committer: committer,
		})
		r.result.Mapping = append(r.result.Mapping, RepairMapping{
			Commit: commit, Tree: tree,
			Author: author.display(), Committer: committer.display(),
		})
		r.printf("  plan     %s %s -> %s", short(commit), author.display(), r.target)
	}

	if len(unexpected) > 0 {
		slices.Sort(unexpected)
		return nil, fmt.Errorf("%d identity header(s) in the range are not ones this run was told to "+
			"expect:\n%s\nPass each address to --expect-identity to confirm it should be rewritten as %s, "+
			"or narrow the range", len(unexpected), strings.Join(unexpected, "\n"), r.target)
	}
	return steps, nil
}

// apply rebuilds, signs, writes and re-reads every commit in the plan.
func (r *repairer) apply(ctx context.Context, steps []repairStep) error {
	rewritten := make(map[string]string, len(steps))

	for index, step := range steps {
		remapped := make([]string, len(step.parents))
		for i, parent := range step.parents {
			remapped[i] = parent
			if replacement, ok := rewritten[parent]; ok {
				remapped[i] = replacement
			}
		}

		r.warnStaleMergetag(step, remapped)

		newSHA, err := r.rebuild(ctx, step, remapped)
		if err != nil {
			return err
		}
		if err := r.assertRepaired(ctx, step, remapped, newSHA); err != nil {
			return err
		}

		rewritten[step.commit] = newSHA
		r.result.Mapping[index].NewCommit = newSHA
		r.result.Repaired++
		r.printf("  repaired %s -> %s", short(step.commit), short(newSHA))
	}

	tip := rewritten[r.result.ExpectedTip]
	tree, err := r.repo.treeOf(ctx, tip)
	if err != nil {
		return err
	}
	if tree != r.result.Tree {
		return fmt.Errorf("the repaired tip %s has tree %s but the original tip %s has tree %s; "+
			"the repair changed the content of the branch and was not applied to any ref",
			tip, tree, r.result.ExpectedTip, r.result.Tree)
	}

	r.result.Tip = tip
	r.printf("Repaired %d commit(s) in %s..%s as %s.", r.result.Repaired, short(r.result.Base),
		short(r.result.ExpectedTip), r.target)
	r.printf("Repaired tip %s carries tree %s, the same tree as %s.", tip, short(tree), short(r.result.ExpectedTip))
	r.printf("No ref was moved and nothing was pushed. Publish with:")
	r.printf("  git push origin %s:refs/heads/<branch> --force-with-lease=<branch>:%s", tip, r.result.ExpectedTip)
	return nil
}

// warnStaleMergetag says so when a merge's embedded tag now names a commit
// that no longer exists under that SHA.
//
// A mergetag carries the whole tag object, including its tagger's signature
// over its own "object <sha>" line. Repointing it would break that signature,
// and this run has no key to remake it with, so the header is left alone.
// Nothing is corrupt, but "git log --show-signature" on the repaired merge then
// describes a merged tag matching none of its parents.
func (r *repairer) warnStaleMergetag(step repairStep, remapped []string) {
	moved := make(map[string]bool)
	for index, parent := range step.parents {
		if remapped[index] != parent {
			moved[parent] = true
		}
	}
	if len(moved) == 0 {
		return
	}
	merge, err := decodeCommit(step.raw)
	if err != nil {
		return
	}
	stale := staleMergeTags(mergeTags(merge), moved)
	if len(stale) == 0 {
		return
	}

	r.warn("the merge %s carries a mergetag naming %s, which this repair rewrote; the embedded tag is "+
		"signed by its tagger, so it cannot be repointed at the rewritten parent and now matches no parent.",
		short(step.commit), strings.Join(stale, ", "))
}

// warnCompatObjectFormat says so when a repaired commit will come out carrying
// one signature where git wrote two.
//
// A repository in hash-algorithm compatibility mode stores objects under one
// format and mirrors them under the other, and git signs such a commit once per
// format. This run rebuilds the stored object and signs that, so only one
// header can be put back. git checks the one that remains, so nothing reads as
// unsigned, but a commit that carried two attestations comes out carrying one.
func (r *repairer) warnCompatObjectFormat(ctx context.Context) error {
	compat, err := r.repo.compatObjectFormat(ctx)
	if err != nil {
		return err
	}
	if compat == "" {
		return nil
	}

	r.warn("this repository stores %s objects and mirrors them under %s (extensions.compatObjectFormat), "+
		"so git signs each commit once per format. A repaired commit gets a fresh %s signature and loses "+
		"the %s one: recreating that means signing the mirrored object this run never builds.",
		r.format, compat, r.format, compat)
	return nil
}

// rebuild produces one repaired commit object and returns the SHA git stored
// it under.
func (r *repairer) rebuild(ctx context.Context, step repairStep, parents []string) (string, error) {
	// unsignedObject strips both signature header spellings, so whatever the
	// broken chain carried is gone before the payload is built rather than
	// being replaced alongside itself.
	payload, err := unsignedObject(step.raw, parents)
	if err != nil {
		return "", fmt.Errorf("%s: %w", step.commit, err)
	}
	payload, err = replaceIdents(payload, r.target)
	if err != nil {
		return "", fmt.Errorf("%s: %w", step.commit, err)
	}
	// The service reads the request body as text, so a byte that is not valid
	// UTF-8 comes back signed as U+FFFD and the signature covers different
	// bytes than the commit does. Refusing here names the cause; the read-back
	// check below would only report a mismatch.
	if !utf8.Valid(payload) {
		return "", fmt.Errorf("%s holds bytes that are not valid UTF-8; the signing service reads the "+
			"payload as text, so the signature would not match the commit", short(step.commit))
	}

	signature, err := r.sign(ctx, payload)
	if err != nil {
		return "", fmt.Errorf("%s: %w", short(step.commit), err)
	}
	return r.repo.hashObject(ctx, withSignature(payload, signature, r.format))
}

// sign asks the service to sign the rebuilt commit bytes.
func (r *repairer) sign(ctx context.Context, payload []byte) ([]byte, error) {
	result, err := r.signer.Sign(ctx, string(payload), r.opts.KeyID)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	if !strings.Contains(result.Signature, pgpArmorMarker) {
		return nil, fmt.Errorf("the signing service returned no PGP signature: %q", result.Signature)
	}
	return []byte(strings.Trim(result.Signature, "\n")), nil
}

// assertRepaired re-reads the object git stored and checks every invariant
// this command promises against it.
//
// Checking the stored object rather than the bytes in hand is the point: the
// promise is about what is now in the repository, and the caller's next step is
// to publish it.
func (r *repairer) assertRepaired(ctx context.Context, step repairStep, parents []string, newSHA string) error {
	raw, err := r.repo.catFileCommit(ctx, newSHA)
	if err != nil {
		return err
	}
	refuse := func(why string, args ...any) error {
		return fmt.Errorf("%s was rebuilt as %s, but %s; no ref was moved",
			short(step.commit), short(newSHA), fmt.Sprintf(why, args...))
	}

	author, committer, err := readIdents(raw)
	if err != nil {
		return refuse("its identity headers are unreadable: %v", err)
	}
	// Checked in the order git writes the headers, so a commit that is wrong in
	// both places always names the same one first.
	for _, pair := range []struct {
		header   string
		got, was ident
	}{
		{authorHeader, author, step.author},
		{committerHeader, committer, step.committer},
	} {
		header, got, was := pair.header, pair.got, pair.was
		if !got.matches(r.target) {
			return refuse("its %s header reads %s rather than %s", header, got.display(), r.target)
		}
		if got.when != was.when {
			return refuse("its %s timestamp reads %q rather than the original %q", header, got.when, was.when)
		}
	}

	tree, err := treeHeader(raw)
	if err != nil {
		return refuse("its tree header is unreadable: %v", err)
	}
	if tree != step.tree {
		return refuse("it points at tree %s rather than the original %s", tree, step.tree)
	}

	message, err := messageBody(raw)
	if err != nil {
		return refuse("its message is unreadable: %v", err)
	}
	if !bytes.Equal(message, step.message) {
		return refuse("its message bytes differ from the original")
	}

	got, err := parentsOf(raw)
	if err != nil {
		return refuse("its parents are unreadable: %v", err)
	}
	if !slices.Equal(got, parents) {
		return refuse("its parents are %v rather than the remapped %v", got, parents)
	}

	if good, detail := r.key.verify(raw, r.format); !good {
		return refuse("its signature does not verify against the service key: %s", detail)
	}
	return nil
}

// treeOf returns the tree a commit points at.
func (r *repo) treeOf(ctx context.Context, sha string) (string, error) {
	return r.gitLine(ctx, "rev-parse", "--verify", sha+"^{tree}")
}
