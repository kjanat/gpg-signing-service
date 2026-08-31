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
	/** `X-GitHub-Delivery`; GitHub's id for the attempt, and what a redelivery reuses. */
	id: string;
	/** `installation.id`, when the event carries one. */
	installationId: number | null;
}
