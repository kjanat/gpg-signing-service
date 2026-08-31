/**
 * Deciding *what a verified delivery is allowed to be about*.
 *
 * The HMAC in `#utils/github-webhook` answers one question — did this come from
 * a holder of the webhook secret — and it is easy to mistake that for the whole
 * answer. It is not. One App has one webhook secret and many installations, so
 * the secret proves the **sender** and says nothing about the **subject**: a
 * delivery for a repository this deployment has no business touching carries
 * exactly the same valid signature as one for the repository it was set up for.
 * On a service whose entire purpose is to sign things, "authenticated" and
 * "authorized to make me sign for this repo" being the same check is how a
 * webhook secret becomes authority over every repository the App is installed
 * on.
 *
 * So authorization is a separate decision, taken here, against a list only an
 * operator can write.
 *
 * ### Why the allowlist entries are pairs
 *
 * An entry is `<installationId>:<owner>/<repo>` and not a bare repository,
 * because two independent lists — allowed installations, allowed repositories —
 * authorize every combination of the two. That is the cross-installation
 * confusion this exists to close: installation A, which legitimately holds the
 * secret's App, could name repository R belonging to installation B and be
 * waved through by a repository list that never meant to grant A anything.
 * Binding the two in one entry means a repository is only ever authorized under
 * the installation the operator paired it with.
 *
 * ### Why the decision carries the repository
 *
 * {@link WebhookAuthorization.repository} is copied from the **allowlist
 * entry**, never from the payload. A handler that reads
 * `payload.repository.full_name` is letting the delivery name its own subject
 * again, one layer further in — and it would do so having passed a check, which
 * is worse than having no check. Handing back the operator's own spelling makes
 * the safe path the short one.
 *
 * ### Fail closed, in every direction
 *
 * An unset list authorizes no installation and no repository. A list with one
 * malformed entry is refused whole rather than partially applied: a typo must
 * not silently drop a grant, and it must certainly not silently widen one. A
 * delivery naming an installation whose id cannot be read is refused rather
 * than treated as unscoped. Each of those is a case where the tempting
 * behaviour is the permissive one.
 */

import type { WebhookAuthorization } from "#types";
import { GitHubAppError } from "#utils/github-app";

/** The variable an operator writes the allowlist into. */
export const ALLOWLIST_VAR = "GITHUB_APP_ALLOWED_REPOSITORIES";

/**
 * One `<installation, repository>` grant.
 *
 * `repository` is stored lower-cased for comparison, and `spelling` keeps what
 * the operator typed so the decision can hand that back rather than a
 * normalisation of it. GitHub logins and repository names are case-insensitive
 * for uniqueness but case-preserving for display, so comparing case-sensitively
 * would let `Kjanat/Repo` and `kjanat/repo` be different grants for one
 * repository — a difference no operator intends and every operator eventually
 * types.
 */
interface AllowlistEntry {
	installationId: number;
	/** Lower-cased `owner/repo`, for comparison. */
	repository: string;
	/** `owner/repo` as the operator wrote it, for the decision to hand back. */
	spelling: string;
}

/**
 * An owner login, exactly as GitHub allows one.
 *
 * Alphanumeric first character, alphanumerics and hyphens after it, 39
 * characters at most. Nothing conservative is given up here — this *is*
 * GitHub's rule — so a login this refuses is not a login.
 */
const OWNER_SEGMENT = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})";

/**
 * A repository name, which is not the same shape as an owner.
 *
 * A repository *may* begin with `.`, `_` or `-`: `owner/.github` is the
 * repository GitHub's own documentation asks you to create, and refusing it
 * would refuse deliveries about it and — worse — make an operator who
 * allowlisted it brick every delivery, since a malformed entry refuses the
 * whole list. So the leading character is unrestricted within the charset, and
 * the two names excluded are the two that are not path segments: `.` and `..`.
 * The value still reaches a URL path, which is why that exclusion is here and
 * not left to the caller.
 */
const REPO_SEGMENT = "(?!\\.{1,2}(?:$|/))[A-Za-z0-9._-]{1,100}";

/** `owner/repo`, anchored. */
const FULL_NAME_PATTERN = new RegExp(`^${OWNER_SEGMENT}/${REPO_SEGMENT}$`);

/** `<digits>:<owner>/<repo>`, anchored. */
const ENTRY_PATTERN = new RegExp(`^(\\d{1,19}):(${OWNER_SEGMENT}/${REPO_SEGMENT})$`);

/** Is `value` a well-formed `owner/repo`? */
export function isRepositoryFullName(value: string): boolean {
	return FULL_NAME_PATTERN.test(value);
}

/**
 * The configured grants, or a `misconfigured` throw.
 *
 * @param raw - `GITHUB_APP_ALLOWED_REPOSITORIES`, unset or comma-separated
 * @throws {GitHubAppError} when any entry is malformed. The message quotes the
 *   offending entry, which is operator-authored configuration rather than
 *   anything a caller supplied, and the alternative — "one of your entries is
 *   wrong" — is a variable an operator has to bisect by hand.
 */
export function parseRepositoryAllowlist(raw: string | undefined): AllowlistEntry[] {
	if (raw === undefined) {
		return [];
	}

	const entries: AllowlistEntry[] = [];

	for (const piece of raw.split(",")) {
		const entry = piece.trim();
		if (entry === "") {
			// A trailing comma, or a line an operator broke across two. Skipped
			// rather than refused: it grants nothing and means nothing, so failing
			// on it would be a deployment broken by whitespace.
			continue;
		}

		const match = ENTRY_PATTERN.exec(entry);
		if (match === null) {
			throw new GitHubAppError(
				`${ALLOWLIST_VAR} entry ${JSON.stringify(entry)} is not <installationId>:<owner>/<repo>`,
				{ misconfigured: true },
			);
		}

		const installationId = Number(match[1]);
		const spelling = match[2] as string;

		// `\d{1,19}` admits values above 2^53. Refused rather than clamped: a
		// silently truncated installation id is a grant to an installation the
		// operator did not write down.
		if (!Number.isSafeInteger(installationId) || installationId <= 0) {
			throw new GitHubAppError(`${ALLOWLIST_VAR} entry ${JSON.stringify(entry)} has an unusable installation id`, {
				misconfigured: true,
			});
		}

		entries.push({ installationId, repository: spelling.toLowerCase(), spelling });
	}

	return entries;
}

/** What a payload says about itself, before any of it is believed. */
interface DeliverySubject {
	/** Whether the payload has an `installation` object at all. */
	installationPresent: boolean;
	/** Its `id`, when that is a usable one. */
	installationId: number | null;
	/** Whether the payload has a `repository` object at all. */
	repositoryPresent: boolean;
	/** Its `full_name`, when that is a well-formed `owner/repo`. */
	repositoryFullName: string | null;
}

/** Is `value` a JSON object (and not null, and not an array)? */
function isObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * The subject a payload claims, read defensively.
 *
 * Presence and readability are tracked separately on purpose. "No `repository`
 * key" and "a `repository` key whose `full_name` is a number" are the same
 * value — null — and opposite situations: the first is an event that is not
 * about a repository, the second is an event that is about one this service
 * cannot name. Collapsing them would authorize the second as though it were the
 * first.
 */
export function deliverySubject(payload: unknown): DeliverySubject {
	if (!isObject(payload)) {
		return {
			installationPresent: false,
			installationId: null,
			repositoryPresent: false,
			repositoryFullName: null,
		};
	}

	const installation = payload.installation;
	const installationPresent = installation !== undefined && installation !== null;
	let installationId: number | null = null;
	if (isObject(installation)) {
		const id = installation.id;
		installationId = typeof id === "number" && Number.isSafeInteger(id) && id > 0 ? id : null;
	}

	const repository = payload.repository;
	const repositoryPresent = repository !== undefined && repository !== null;
	let repositoryFullName: string | null = null;
	if (isObject(repository)) {
		const fullName = repository.full_name;
		repositoryFullName = typeof fullName === "string" && isRepositoryFullName(fullName) ? fullName : null;
	}

	return { installationPresent, installationId, repositoryPresent, repositoryFullName };
}

/** Why a delivery was refused. Logged; never sent to the caller in this detail. */
export type AuthorizationRefusal =
	/** An `installation` object whose id is missing, negative, or not a number. */
	| "installation_unreadable"
	/** A `repository` object with no usable `full_name`. */
	| "repository_unnameable"
	/** A repository-scoped delivery that names no installation to scope it to. */
	| "repository_without_installation"
	/** The `<installation, repository>` pair is not on the allowlist. */
	| "pair_not_allowed"
	/** The installation appears in no allowlist entry. */
	| "installation_not_allowed";

/** Authorized, with the scope; or refused, with the reason. */
export type AuthorizationDecision =
	| { allowed: true; authorization: WebhookAuthorization }
	| { allowed: false; reason: AuthorizationRefusal };

/**
 * May this delivery be acted upon, and on what?
 *
 * Pure: no bindings, no clock, no network. The order of the checks is the
 * policy, so it is written as one list rather than as nested conditions.
 *
 * @param allowlist - The parsed grants; an empty list authorizes no subject
 * @param payload - The verified payload, exactly as parsed from the signed bytes
 */
export function authorizeDelivery(allowlist: readonly AllowlistEntry[], payload: unknown): AuthorizationDecision {
	const subject = deliverySubject(payload);

	// An installation this service cannot identify is not "no installation". A
	// payload carrying `installation: {}` would otherwise fall through to the
	// unscoped branch and be accepted, which reads as harmless right up until a
	// handler decides that an accepted delivery is one it may act on.
	if (subject.installationPresent && subject.installationId === null) {
		return { allowed: false, reason: "installation_unreadable" };
	}

	if (subject.repositoryPresent) {
		if (subject.repositoryFullName === null) {
			return { allowed: false, reason: "repository_unnameable" };
		}

		// Every delivery from an installed App carries `installation`. One that
		// names a repository without it did not come from an installation of this
		// App, whatever its signature says — and there is no installation to scope
		// the grant to, so there is nothing to authorize it against.
		if (subject.installationId === null) {
			return { allowed: false, reason: "repository_without_installation" };
		}

		const wanted = subject.repositoryFullName.toLowerCase();
		const grant = allowlist.find(
			(entry) => entry.installationId === subject.installationId && entry.repository === wanted,
		);

		if (grant === undefined) {
			return { allowed: false, reason: "pair_not_allowed" };
		}

		return {
			allowed: true,
			authorization: {
				scope: "repository",
				installationId: grant.installationId,
				// The operator's spelling, not `subject.repositoryFullName`. See the
				// module comment: the payload does not get to name its own subject,
				// not even in a form this code just compared and found equal.
				repository: grant.spelling,
			},
		};
	}

	if (subject.installationId !== null) {
		const known = allowlist.some((entry) => entry.installationId === subject.installationId);

		if (!known) {
			return { allowed: false, reason: "installation_not_allowed" };
		}

		return {
			allowed: true,
			authorization: { scope: "installation", installationId: subject.installationId, repository: null },
		};
	}

	// Neither an installation nor a repository. The App-level `ping` GitHub sends
	// when a webhook URL is saved is the event that lands here, and an operator
	// checking their setup before they have written an allowlist needs it to
	// answer. It authorizes nothing — there is no installation to mint a token
	// for and no repository to touch — so accepting it grants the sender exactly
	// what it named, which is nothing.
	return { allowed: true, authorization: { scope: "none", installationId: null, repository: null } };
}
