package gitsign

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/kjanat/gpg-signing-service/client/pkg/client"
)

// pgpArmorMarker is the only response shape this package can embed. The
// service can also produce PKCS#7 for gpg.format=x509, but that is a different
// header and a different reconstruction.
const pgpArmorMarker = "-----BEGIN PGP SIGNATURE-----"

// defaultBranchFallback is used when the caller names no default branch.
const defaultBranchFallback = "master"

// sha1ObjectFormat is the only hash algorithm whose gpgsig header spelling this
// package produces.
const sha1ObjectFormat = "sha1"

// Signer is the slice of the signing-service SDK this package needs.
// *client.Client satisfies it.
type Signer interface {
	PublicKey(ctx context.Context, keyID string) (string, error)
	Sign(ctx context.Context, commitData, keyID string) (*client.SignResult, error)
}

// Mark records what the rewrite did to one commit.
type Mark string

const (
	// MarkSigned means the rewrite embedded a fresh signature.
	MarkSigned Mark = "signed"
	// MarkStripped means the commit carried a signature the rewrite removed
	// and could not replace, because the key does not cover its committer.
	MarkStripped Mark = "stripped"
	// MarkReparent means the commit was rewritten only to follow a rewritten
	// parent; it never carried a signature.
	MarkReparent Mark = "reparent"
)

// Rewrite is one commit's outcome.
type Rewrite struct {
	Commit    string `json:"commit"`
	NewCommit string `json:"newCommit"`
	Mark      Mark   `json:"mark"`
}

// Result summarizes a run.
type Result struct {
	Branch     string    `json:"branch"`
	Base       string    `json:"base"`
	Head       string    `json:"head"`
	Tip        string    `json:"tip"`
	Scanned    int       `json:"commitsScanned"`
	Signed     int       `json:"commitsSigned"`
	Rewrites   []Rewrite `json:"rewrites,omitempty"`
	Warnings   []string  `json:"warnings,omitempty"`
	RefUpdated bool      `json:"refUpdated"`
	Pushed     bool      `json:"pushed"`
}

// Options configures a run.
type Options struct {
	// Dir is the working tree to operate on; empty means the current directory.
	Dir string
	// DefaultBranch names the branch that gets the last-signed-commit scan
	// rather than a merge base. Defaults to "master".
	DefaultBranch string
	// Base is an explicit exclusive lower bound for the range. Empty means
	// resolve one.
	Base string
	// KeyID selects the signing key; empty uses the service default.
	KeyID string
	// AllowResign permits rewriting commits that already carry a signature.
	AllowResign bool
	// SignOthers signs commits whose committer the key does not cover.
	SignOthers bool
	// ScanLimit bounds the last-signed-commit scan; 0 means unbounded.
	ScanLimit int
	// Out receives progress output; nil discards it.
	Out io.Writer
}

// ResignError reports a run refused because it would rewrite commits that
// already carry a signature.
type ResignError struct {
	// Stale is how many commits the run would have rewritten in total.
	Stale int
	// Resign lists the already-signed commits among them.
	Resign []string
	// Report is the per-commit explanation, one line each.
	Report []string
}

func (e *ResignError) Error() string {
	return fmt.Sprintf(
		"signing %d commit(s) would rewrite %d already-signed commit(s) below the tip; "+
			"move the base forward or re-run with --allow-resign (dispatch with allow_resign from CI)",
		e.Stale, len(e.Resign),
	)
}

// Run applies signatures to the commits in base..HEAD and moves the local HEAD
// ref to the rewritten tip.
//
// It never pushes. The rewritten commits have new SHAs, so publishing them
// means a force push, and that decision belongs to the operator.
func Run(ctx context.Context, signer Signer, opts Options) (*Result, error) {
	if opts.ScanLimit < 0 {
		return nil, fmt.Errorf("scan-limit must be a positive integer, got %d", opts.ScanLimit)
	}
	if opts.DefaultBranch == "" {
		opts.DefaultBranch = defaultBranchFallback
	}
	if opts.Out == nil {
		opts.Out = io.Discard
	}

	s := &session{
		repo:   &repo{dir: opts.Dir},
		signer: signer,
		opts:   opts,
		result: &Result{},
	}

	branch, err := s.repo.currentBranch(ctx)
	if err != nil {
		return nil, err
	}
	s.result.Branch = branch

	// git names the signature header after the repository's hash algorithm:
	// gpgsig for sha1, gpgsig-sha256 for sha256. This package writes the sha1
	// spelling only, and go-git's object decoder is compiled for 20-byte
	// hashes, so a sha256 repository's tree and parent lines do not survive a
	// round trip either. Refuse while the cause is still visible rather than
	// failing somewhere downstream of a written object.
	format, err := s.repo.objectFormat(ctx)
	if err != nil {
		return nil, err
	}
	if format != sha1ObjectFormat {
		return nil, fmt.Errorf("this repository uses the %s object format, whose signature header is "+
			"gpgsig-%s; sign-commit writes the sha1 gpgsig header only", format, format)
	}

	armored, err := signer.PublicKey(ctx, opts.KeyID)
	if err != nil {
		return nil, fmt.Errorf("could not fetch the public key: %w", err)
	}
	s.key, err = newSigningKey(armored)
	if err != nil {
		return nil, err
	}
	s.identities, err = s.key.identities(time.Now())
	if err != nil {
		return nil, err
	}

	if err := s.run(ctx); err != nil {
		return s.result, err
	}
	return s.result, nil
}

// session carries the state of one run.
type session struct {
	repo       *repo
	signer     Signer
	opts       Options
	key        *signingKey
	identities map[string]bool
	result     *Result
}

func (s *session) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(s.opts.Out, format+"\n", args...)
}

// warn records a message that the operator needs after the log scrolls past.
func (s *session) warn(format string, args ...any) {
	message := fmt.Sprintf(format, args...)
	s.result.Warnings = append(s.result.Warnings, message)
	_, _ = fmt.Fprintf(s.opts.Out, "warning: %s\n", message)
}

func (s *session) run(ctx context.Context) error {
	head, err := s.repo.head(ctx)
	if err != nil {
		return err
	}
	s.result.Head = head
	s.result.Tip = head

	base, err := s.resolveBase(ctx)
	if err != nil {
		return err
	}
	s.result.Base = base

	commits, err := s.repo.revList(ctx, base)
	if err != nil {
		return err
	}
	s.result.Scanned = len(commits)
	if len(commits) == 0 {
		s.reportEmptyRange(base, head)
		return nil
	}

	work, err := s.classify(ctx, commits)
	if err != nil {
		return err
	}
	if len(work.stale) == 0 {
		s.reportNothingStale(work, base)
		return nil
	}
	if err := s.guard(work, commits); err != nil {
		return err
	}
	return s.rewrite(ctx, work, commits, base, head)
}

// short is the abbreviated SHA used in progress output.
func short(sha string) string {
	if len(sha) <= 8 {
		return sha
	}
	return sha[:8]
}

// resolveBase decides the exclusive lower bound of the range.
func (s *session) resolveBase(ctx context.Context) (string, error) {
	branch := s.result.Branch

	if s.opts.Base == "" && branch == s.opts.DefaultBranch {
		return s.lastSigned(ctx)
	}

	if s.opts.ScanLimit > 0 {
		// The scan is the only consumer of the limit, so a limit paired with a
		// pinned range is a silent no-op the operator would never see.
		pinned := fmt.Sprintf("%s is not %s, so the range starts at the merge base", branch, s.opts.DefaultBranch)
		if s.opts.Base != "" {
			pinned = fmt.Sprintf("base=%s pins the range", s.opts.Base)
		}
		s.warn("scan-limit=%d was discarded because %s; the scan for the last signed commit only runs when base is blank",
			s.opts.ScanLimit, pinned)
	}

	if s.opts.Base != "" {
		return s.repo.resolveCommit(ctx, s.opts.Base)
	}
	return s.repo.mergeBase(ctx, "origin/"+s.opts.DefaultBranch)
}

// lastSigned walks back from HEAD for the newest commit this key already
// verifies, which is where the branch was last left in a good state.
func (s *session) lastSigned(ctx context.Context) (string, error) {
	args := []string{"rev-list"}
	if s.opts.ScanLimit > 0 {
		args = append(args, "--max-count="+strconv.Itoa(s.opts.ScanLimit))
	}
	args = append(args, detachedHead)

	revisions, err := s.repo.git(ctx, args...)
	if err != nil {
		return "", err
	}
	objects, err := s.repo.catFileBatch(ctx, revisions)
	if err != nil {
		return "", err
	}

	for _, object := range objects {
		signed, err := isSigned(object.raw)
		if err != nil {
			return "", err
		}
		if !signed {
			continue
		}
		if good, _ := s.key.verify(object.raw); good {
			return object.sha, nil
		}
	}

	scope := detachedHead
	if s.opts.ScanLimit > 0 {
		scope = fmt.Sprintf("the last %d commit(s) on HEAD", s.opts.ScanLimit)
	}
	return "", fmt.Errorf("no verified commit in %s; pass base explicitly", scope)
}
