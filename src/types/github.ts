/**
 * Shapes for the GitHub App integration.
 *
 * Only what a *verified* delivery is known to be. The payload itself is
 * deliberately not modelled: it is a document of GitHub's choosing whose shape
 * varies per event, the scaffold reads one field out of it, and a hand-written
 * interface for the rest would be a claim this repository cannot keep true.
 */

/** What is known about a delivery once its signature has been checked. */
export interface WebhookDelivery {
	/** `X-GitHub-Event`, e.g. `ping`, `push`, `installation`. */
	event: string;
	/**
	 * `X-GitHub-Delivery`, when it is present and well formed; otherwise null.
	 *
	 * Nullable rather than defaulted, because a default is a shared key: two
	 * deliveries that both arrived without an id and were both recorded as
	 * `"unknown"` would dedupe against each other, and an attacker able to claim
	 * that name once could suppress every later id-less delivery. `webhookReplayGuard`
	 * refuses null outright, so nothing that acts on a delivery ever sees one.
	 */
	id: string | null;
	/** `installation.id`, when the event carries one. */
	installationId: number | null;
}

/**
 * What a verified delivery is *allowed to be about*.
 *
 * The decision `githubWebhookAuthorize` reached, and — this is the part that
 * matters — the only place downstream is permitted to learn which repository a
 * delivery concerns. Reading `payload.repository.full_name` directly would let
 * a delivery name its own subject, which is precisely the confusion the
 * allowlist exists to prevent: a webhook secret proves the *sender*, never the
 * scope. `repository` below is copied from the operator's allowlist entry, not
 * from the wire, so a handler acting on it is acting on a string an operator
 * typed.
 */
export interface WebhookAuthorization {
	/**
	 * How much authority this delivery carries.
	 *
	 * - `repository` — an allowlisted `<installation, repository>` pair. The one
	 *   scope under which a handler may touch a repository.
	 * - `installation` — the delivery names an allowlisted installation and no
	 *   repository (`installation`, `installation_repositories`, org-level
	 *   events). Authorizes nothing repository-shaped.
	 * - `none` — the delivery names neither. The App-level `ping` is the only
	 *   event that realistically lands here. Authorizes nothing at all.
	 */
	scope: "repository" | "installation" | "none";
	/** The allowlisted installation, or null at `none` scope. */
	installationId: number | null;
	/**
	 * The allowlisted repository as `owner/repo`, or null below `repository`
	 * scope. **The operator's spelling, never the payload's.**
	 */
	repository: string | null;
}

/** What the replay guard decided about a delivery id it had not seen before. */
export interface WebhookReplay {
	/** When this delivery id was first claimed, in epoch milliseconds. */
	firstSeen: number;
}
