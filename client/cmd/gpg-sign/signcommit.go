package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/kjanat/gpg-signing-service/client/pkg/gitsign"
	"github.com/spf13/cobra"
)

// Sign-commit command
var signCommitCmd = &cobra.Command{
	Use:   "sign-commit",
	Short: "Apply signatures to commits in the current repository",
	Long: `Signs the commits in base..HEAD by rewriting each commit object with an
embedded PGP signature, then moves the local HEAD ref to the rewritten tip.

This is destructive. Embedding a signature changes a commit's SHA, so every
descendant is rewritten too, and publishing the result requires a force push.
The command stops at the local ref update and never pushes.

The range starts at --base when given. Otherwise, on the default branch it
starts at the last commit this key already verifies, and on any other branch at
the merge base with origin/<default-branch>.

Requires the git and gpg binaries on PATH.

Example:
  gpg-sign sign-commit --key-id=62E75E54497815DD
  gpg-sign sign-commit --base=origin/master --allow-resign`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		keyID, _ := cmd.Flags().GetString("key-id")
		base, _ := cmd.Flags().GetString("base")
		defaultBranch, _ := cmd.Flags().GetString("default-branch")
		allowResign, _ := cmd.Flags().GetBool("allow-resign")
		signOthers, _ := cmd.Flags().GetBool("sign-others")
		scanLimit, _ := cmd.Flags().GetInt("scan-limit")
		repoDir, _ := cmd.Flags().GetString("repo")

		if scanLimit < 0 {
			return fmt.Errorf("--scan-limit must be a positive integer, got %d", scanLimit)
		}

		c, err := newClient()
		if err != nil {
			return fmt.Errorf("failed to create client: %w", err)
		}

		// One timeout for the whole walk, not per request: a range of N commits
		// makes N signing calls, and the per-request default would cut the run
		// short partway through a rewrite.
		ctx, cancel := context.WithTimeout(context.Background(), timeout*signCommitTimeoutFactor)
		defer cancel()

		// JSON output is a single document, so progress lines cannot go to
		// stdout in that mode.
		out := os.Stdout
		if jsonOutput {
			out = os.Stderr
		}

		result, err := gitsign.Run(ctx, c, gitsign.Options{
			Dir:           repoDir,
			DefaultBranch: defaultBranch,
			Base:          base,
			KeyID:         keyID,
			AllowResign:   allowResign,
			SignOthers:    signOthers,
			ScanLimit:     scanLimit,
			Out:           out,
		})
		if err != nil {
			// The guard already printed its per-commit report; wrapping it
			// again would bury the explanation under a generic prefix.
			var blocked *gitsign.ResignError
			if errors.As(err, &blocked) {
				return blocked
			}
			return fmt.Errorf("sign-commit failed: %w", err)
		}

		if jsonOutput {
			return outputJSON(result)
		}
		return nil
	},
}

// signCommitTimeoutFactor scales the per-request timeout into a budget for a
// whole range of commits.
const signCommitTimeoutFactor = 20

func init() {
	signCommitCmd.Flags().String("key-id", "", "Key identifier (uses default if not specified)")
	signCommitCmd.Flags().String("base", "", "Exclusive lower bound of the range (default: resolved)")
	signCommitCmd.Flags().String("default-branch", "master", "Branch that gets the last-signed-commit scan")
	signCommitCmd.Flags().Bool("allow-resign", false, "Permit rewriting commits that already carry a signature")
	signCommitCmd.Flags().Bool("sign-others", false, "Also sign commits whose committer the key does not cover")
	signCommitCmd.Flags().Int("scan-limit", 0, "Bound the last-signed-commit scan (0 = unbounded)")
	signCommitCmd.Flags().String("repo", "", "Repository working tree (default: current directory)")
}
