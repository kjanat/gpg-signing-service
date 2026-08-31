/**
 * Publishing what a commit's signature turned out to be, as a GitHub check run.
 *
 * `#utils/push-signing` is the acting path and this is the *reporting* one, and
 * the difference runs through every decision here. Signing rewrites history, so
 * it is protected by a delivery ledger and a budget and an irreversible
 * boundary. A check run says what is already true of a commit — so the same
 * report, published twice, has to converge rather than be prevented.
 *
 * ### Idempotent instead of at-most-once
 *
 * A check run is addressed by `<name, head_sha>`, and both halves are fixed
 * before anything is written: the name is {@link CHECK_RUN_NAME}, a constant in
 * this file, and the sha is read back from the authorized repository's ref
 * rather than taken from the payload. So the same delivery, redelivered, and a
 * different delivery about the same head both name the same check — and the
 * write is a *lookup, then update or create*, which lands on it.
 *
 * That is what makes a lost response safe. A create whose answer never arrived
 * leaves a run that the next attempt finds and updates, so the second effect is
 * "the same check now says the same thing" rather than a second check. The
 * delivery ledger is not asked to protect this and is not touched by it — which
 * is deliberate, because tying an idempotent write to a one-way claim is how a
 * transient GitHub error turns into a check that can never be published.
 *
 * The residual, stated rather than argued away: GitHub's Checks API has no
 * conditional create, so two reports for the *identical* sha that are both
 * in-flight through the lookup can both create a run. Nothing available over
 * this API closes that window. What closes it afterwards is the ordering rule —
 * `listCheckRuns` returns this App's runs sorted by id, and the earliest is the
 * one updated — so every later report converges on the same run rather than
 * alternating between them.
 *
 * ### Nothing here can widen what a delivery may touch
 *
 * The repository, the installation and the key all arrive already decided:
 * the client is bound to a `<installation, repository>` pair the operator
 * allowlisted, and the key is the one that same entry bound. This module takes
 * no repository argument, no installation argument and no payload, so there is
 * no parameter through which a delivery could aim a check run somewhere else.
 * The check *name* is a module constant for the same reason.
 *
 * ### It cannot change what the signing path did
 *
 * Every failure returns a result; none throws past the caller and none touches
 * `webhookRetryable`. A check run that could not be published leaves an audit
 * row and a log line, and the push-signing outcome that was already decided
 * stands exactly as it was.
 */

import type { AnyStoredKey } from "#schemas/keys";
import { isX509Key } from "#schemas/keys";
import type { Env } from "#types";
import type { SignatureFinding, SignatureState } from "#utils/commit-signature";
import { inspectCommitSignature } from "#utils/commit-signature";
import type { CheckRunInput, RepositoryClient } from "#utils/github-repo";
import { extractPublicKey } from "#utils/signing";

/**
 * The check run's name, and the reason it is a constant.
 *
 * It is half of the address a report converges on, so it has to be the same
 * string on every delivery, in every repository, forever — a name that varied
 * with anything would spray one check run per variation and make every one of
 * them permanent. It is also the string that appears in a branch protection
 * rule, which an operator writes once by hand.
 */
export const CHECK_RUN_NAME = "GPG signature";

/**
 * Is check-run reporting switched on for this deployment?
 *
 * A literal `"true"`, the same spelling rule as `githubAppEnabled` and for the
 * same reason. Separate from `GITHUB_APP_ENABLED` because it needs something
 * that flag does not: the App must hold `checks: write`, which is a permission
 * an installation has to *approve* after it is added. Folding this into the
 * existing flag would mean every deployment that upgraded started making calls
 * its installation had not granted, and answering 403 on each one.
 */
export function checkRunsEnabled(env: Pick<Env, "GITHUB_APP_CHECK_RUNS">): boolean {
	return env.GITHUB_APP_CHECK_RUNS === "true";
}

/**
 * A full 40-character object id, lower case, and nothing else.
 *
 * The sha comes back from GitHub, and it reaches a URL path and a markdown
 * summary this service publishes under its own name. Requiring the shape a
 * commit id actually has costs nothing on a real response and means a
 * surprising one is refused rather than rendered.
 */
const SHA_PATTERN = /^[0-9a-f]{40}$/;

/** Why a report was not published. */
export type CheckReportRefusal =
	/** `GITHUB_APP_CHECK_RUNS` is not `"true"`. No GitHub call was made. */
	| "disabled"
	/** The bound key is X.509, which signs no `gpgsig` this service can check. */
	| "unsupported_key"
	/** The branch is gone, so there is no head to report on. */
	| "branch_missing"
	/** `GITHUB_APP_ID` is not a number, so our own check runs are unidentifiable. */
	| "app_id_unusable"
	/** The ref, or the commit read back, did not name a usable object id. */
	| "unusable_sha";

/** How a reporting attempt ended. */
export type CheckReportResult =
	| {
			outcome: "published";
			sha: string;
			state: SignatureState;
			finding: SignatureFinding;
			conclusion: CheckRunInput["conclusion"];
			checkRunId: number;
			/** Which of the two writes happened, for the audit row and the log. */
			action: "created" | "updated";
	  }
	| { outcome: "skipped"; reason: CheckReportRefusal }
	| { outcome: "failed"; reason: string };

/** The conclusion each state earns, and nothing stronger. */
export function conclusionFor(state: SignatureState): CheckRunInput["conclusion"] {
	if (state === "service_key_valid") {
		return "success";
	}

	// `failure` is reserved for the one state that is an accusation: a signature
	// claiming the configured key that does not verify under it. `unsigned`,
	// `other_signer` and `unverifiable` are all things this service has no
	// standing to fail a commit over — an unsigned commit beneath a signed one
	// stays unsigned by design, and somebody else's signature is somebody else's
	// business.
	return state === "invalid_signature" ? "failure" : "neutral";
}

/** The one-line title, per state. */
const TITLES: Record<SignatureState, string> = {
	service_key_valid: "Signed by this service's key",
	other_signer: "Signed by another key",
	unsigned: "Not signed",
	invalid_signature: "Signature does not verify",
	unverifiable: "Signature could not be checked",
};

/**
 * The body of the check run.
 *
 * Everything in it is either a constant from this file, a 40-character object
 * id that matched {@link SHA_PATTERN}, an operator-written key id, or one of
 * the closed-set strings in `#utils/commit-signature`. **No signature, no
 * payload, no token, no key material and no GitHub response text reaches this
 * string** — GitHub's own `reason` is repeated only after being matched against
 * a known set, and it is labelled as GitHub's rather than presented as a
 * finding of ours.
 */
export function checkRunSummary(sha: string, keyId: string, finding: SignatureFinding): string {
	const lines = [
		`Commit \`${sha}\``,
		"",
		`- **State:** \`${finding.state}\` (\`${finding.detail}\`)`,
		`- **Configured signing key:** \`${keyId}\``,
		`- **GitHub's own verification:** \`${finding.github.reason}\` (verified: ${finding.github.verified})`,
		"",
	];

	if (finding.state === "service_key_valid") {
		lines.push(
			"The commit object carries an OpenPGP signature made by the key this deployment binds to this repository, and it verifies over the commit's own bytes.",
		);
	} else if (finding.state === "invalid_signature") {
		lines.push(
			"The commit carries an OpenPGP signature naming this deployment's signing key that does not verify under it.",
		);
	} else if (finding.state === "other_signer") {
		lines.push(
			"The commit is signed by a key other than the one this deployment binds to this repository. No claim is made about whether that signature is good; GitHub's own verdict is above.",
		);
	} else if (finding.state === "unsigned") {
		lines.push("The commit carries no signature.");
	} else {
		lines.push(
			"The bytes GitHub reported for this commit could not be tied back to its own object id, so nothing was established either way. A commit carrying a header this service does not model reaches this state with a perfectly good signature.",
		);
	}

	return lines.join("\n");
}

/**
 * Report the signature state of the head of `branch`.
 *
 * @param client - Bound to the authorized `<installation, repository>` pair
 * @param branch - A branch inside that repository
 * @param key - The key that pair's allowlist entry bound
 * @param keyId - Its id, as the operator wrote it
 * @param env - The feature flag, and the App id that tells our runs from others'
 */
export async function reportSignatureCheck(
	env: Pick<Env, "GITHUB_APP_CHECK_RUNS" | "GITHUB_APP_ID">,
	client: RepositoryClient,
	branch: string,
	key: AnyStoredKey,
	keyId: string,
): Promise<CheckReportResult> {
	if (!checkRunsEnabled(env)) {
		// Before anything else, so a deployment that has not opted in makes no
		// GitHub call at all and behaves exactly as it did before this existed.
		return { outcome: "skipped", reason: "disabled" };
	}

	// Derived here rather than taken as an argument, so there is one place that
	// decides which runs are ours and no caller can pass a different answer.
	const appId = Number(env.GITHUB_APP_ID);
	if (!Number.isSafeInteger(appId) || appId <= 0) {
		return { outcome: "skipped", reason: "app_id_unusable" };
	}

	if (isX509Key(key)) {
		// The same refusal `signPushedCommits` makes, for the same reason: an
		// X.509 key has no OpenPGP public half to verify a `gpgsig` against, so
		// there is no question this check could answer.
		return { outcome: "skipped", reason: "unsupported_key" };
	}

	try {
		const ref = await client.getBranch(branch);
		if (ref === null) {
			return { outcome: "skipped", reason: "branch_missing" };
		}

		// **The sha the repository holds**, not the one the delivery claimed. A
		// push payload's `after` is a value the sender chose; this one was read
		// back over an installation token from the authorized repository.
		const sha = ref.sha;
		if (!SHA_PATTERN.test(sha)) {
			return { outcome: "skipped", reason: "unusable_sha" };
		}

		const reported = await client.getCommitVerification(sha);
		if (reported.sha !== sha) {
			// GitHub answered about a different object than the one asked for. That
			// should be impossible; reporting on it anyway would be publishing a
			// verdict for one commit under another commit's name.
			return { outcome: "skipped", reason: "unusable_sha" };
		}

		const finding = await inspectCommitSignature(reported, await extractPublicKey(key.armoredPrivateKey));
		const conclusion = conclusionFor(finding.state);

		const input: CheckRunInput = {
			name: CHECK_RUN_NAME,
			headSha: sha,
			conclusion,
			title: TITLES[finding.state],
			summary: checkRunSummary(sha, keyId, finding),
			completedAt: new Date().toISOString(),
		};

		// Lookup first, so a redelivery — or a second event about the same head —
		// updates the run that exists rather than adding another beside it.
		const existing = await client.listCheckRuns(sha, CHECK_RUN_NAME, appId);
		const target = existing[0];

		if (target !== undefined) {
			await client.updateCheckRun(target.id, input);
			return {
				outcome: "published",
				sha,
				state: finding.state,
				finding,
				conclusion,
				checkRunId: target.id,
				action: "updated",
			};
		}

		const created = await client.createCheckRun(input);

		return {
			outcome: "published",
			sha,
			state: finding.state,
			finding,
			conclusion,
			checkRunId: created,
			action: "created",
		};
	} catch (error) {
		// Token failures, 403s from an installation that has not granted
		// `checks: write`, timeouts, unparseable responses. All of them mean the
		// report did not land, none of them means anything about the signing that
		// happened before it, and the message comes from `GitHubApiError`, which
		// carries a status and never a response body.
		return { outcome: "failed", reason: error instanceof Error ? error.message : "Check run reporting failed" };
	}
}
