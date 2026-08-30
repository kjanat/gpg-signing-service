package main

import (
	"context"
	"fmt"
	"os"

	"github.com/kjanat/gpg-signing-service/client/pkg/gitsign"
	"github.com/spf13/cobra"
)

// repairHistoryCmd rewrites the identity headers of a range of commits and
// signs the result.
//
// It is a separate command rather than a flag on sign-commit because the two
// do categorically different things. sign-commit attests to what a commit
// already says; this rewrites what it says about who wrote it. Overloading the
// ordinary signing path with that would put a provenance rewrite one typo away
// from a routine run.
var repairHistoryCmd = &cobra.Command{
	Use:   "repair-history",
	Short: "Rewrite a range of commits to claim one identity, then sign them",
	Long: `Rebuilds every commit in base..expected-tip so that its author and committer
headers claim --identity, strips any existing signature, signs the reconstructed
payload with the service key, and writes the new objects.

This is dangerous and deliberately hard to invoke by accident. It changes what
history says about who wrote the code, so it exists for one situation: commits
that were manufactured under an identity that never wrote them — a REST
squash-merge attributing a bot as author and "GitHub" as committer, say — which
cannot be signed truthfully without being rebuilt.

Everything else is preserved byte for byte: the tree, the message, each
header's own timestamp and timezone, unknown headers, and the order and
topology of the range, with rewritten parents remapped as the walk goes.

The run fails closed. It refuses unless HEAD is still at --expected-tip, unless
every identity in the range was named with --expect-identity, and unless every
rewritten commit re-reads from the object store with the target identity, the
original timestamps, the original tree and message, the remapped parents and a
signature the service key verifies. The repaired tip must carry the same tree as
the tip it replaces.

No ref is moved and nothing is pushed. The repaired tip is printed for a caller
that has checked it to publish itself:

  git push origin <tip>:refs/heads/<branch> --force-with-lease=<branch>:<expected-tip>

Example:
  gpg-sign repair-history --dry-run \
    --base=a1cdfe318686cac582fc955243966d04236afb58 \
    --expected-tip=42e3400c7b10ee4fbdfc3638801d5776849d1353 \
    --identity="Kaj Kowalski <info@kajkowalski.nl>" \
    --expect-identity=209825114+claude[bot]@users.noreply.github.com \
    --expect-identity=noreply@github.com \
    --expect-identity=info@kajkowalski.nl`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		keyID, _ := cmd.Flags().GetString("key-id")
		base, _ := cmd.Flags().GetString("base")
		expectedTip, _ := cmd.Flags().GetString("expected-tip")
		wanted, _ := cmd.Flags().GetString("identity")
		expect, _ := cmd.Flags().GetStringArray("expect-identity")
		dryRun, _ := cmd.Flags().GetBool("dry-run")
		repoDir, _ := cmd.Flags().GetString("repo")

		c, err := newClient()
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}

		// One budget for the whole walk: the range makes one signing call per
		// commit, and the per-request default would cut a repair short partway
		// through.
		ctx, cancel := context.WithTimeout(commandContext(cmd), timeout*signCommitTimeoutFactor)
		defer cancel()

		out := os.Stdout
		if jsonOutput {
			out = os.Stderr
		}

		result, err := gitsign.Repair(ctx, c, gitsign.RepairOptions{
			Dir:              repoDir,
			Base:             base,
			ExpectedTip:      expectedTip,
			Identity:         wanted,
			ExpectIdentities: expect,
			KeyID:            keyID,
			DryRun:           dryRun,
			Out:              out,
		})
		if err != nil {
			err = fmt.Errorf("repair-history failed: %w", err)
			// Repair hands back a partially filled result alongside its error,
			// and a scripted caller in --json mode has nowhere else to read
			// how far the run got.
			if jsonOutput {
				if writeErr := outputJSON(repairHistoryFailure(result, err)); writeErr != nil {
					return writeErr
				}
			}
			return err
		}

		if jsonOutput {
			return outputJSON(result)
		}
		return nil
	},
}

// repairHistoryResult is the JSON document a failed run emits, the same shape
// contract sign-commit keeps: an error field a caller can branch on without
// parsing progress text.
type repairHistoryResult struct {
	Error  string                `json:"error"`
	Result *gitsign.RepairResult `json:"result,omitempty"`
}

func repairHistoryFailure(result *gitsign.RepairResult, err error) repairHistoryResult {
	return repairHistoryResult{Error: err.Error(), Result: result}
}

func init() {
	repairHistoryCmd.Flags().String("key-id", "", "Key identifier (uses default if not specified)")
	repairHistoryCmd.Flags().String("base", "", "Exclusive lower bound of the range (required)")
	repairHistoryCmd.Flags().String("expected-tip", "", "Commit HEAD must currently point at (required)")
	repairHistoryCmd.Flags().String("identity", "", `Identity to write, as "Name <address>" (required)`)
	repairHistoryCmd.Flags().StringArray("expect-identity", nil,
		"Address the range is allowed to carry; repeat once per identity being replaced (required)")
	repairHistoryCmd.Flags().Bool("dry-run", false, "Validate and print the plan without signing or writing anything")
	repairHistoryCmd.Flags().String("repo", "", "Repository working tree (default: current directory)")

	for _, required := range []string{"base", "expected-tip", "identity", "expect-identity"} {
		// The engine refuses each of these too; marking them here turns a
		// forgotten flag into usage text rather than a run that reaches the
		// repository first.
		_ = repairHistoryCmd.MarkFlagRequired(required)
	}
}
