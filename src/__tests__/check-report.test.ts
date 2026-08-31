/**
 * Reporting a commit's signature state, and the ways a report could lie.
 *
 * The acting path has a suite about not doing the wrong thing. This one is
 * about not *saying* the wrong thing, which fails differently: a check run is a
 * green tick other people act on, so the tests below are written against the
 * ways a passing implementation could still be publishing a claim it did not
 * establish.
 *
 * Four of those are worth naming, because a confirmatory test passes while each
 * is true:
 *
 * - **A reporter that echoed GitHub's `verification.verified` would be green on
 *   every commit GitHub likes, including ones signed by somebody else
 *   entirely.** So every state here is built from real OpenPGP material and the
 *   GitHub verdict in the fixtures is deliberately set to *disagree* with the
 *   finding, in both directions.
 * - **A reporter that verified the signature against the payload GitHub
 *   reported, without tying that payload to the commit, would report a verdict
 *   about bytes rather than about a commit.** So there is a fixture whose
 *   signature and payload verify perfectly and belong to a different object id.
 * - **A reporter that created a check run without looking would spray one per
 *   delivery, and every single-delivery test would still pass.** So the
 *   idempotence tests assert the *number of creates* across repeats, and the
 *   lost-response one asserts it across a create whose answer never arrived.
 * - **A reporter that took the sha from the payload would be right almost
 *   always.** So the endpoint fixtures make `payload.after` a different sha from
 *   the one the ref holds, and the assertion is on the sha the check run
 *   carries.
 */

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import * as openpgp from "openpgp";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import app from "#gpg-signing-service";
import {
	CHECK_RUN_NAME,
	checkRunSummary,
	checkRunsEnabled,
	conclusionFor,
	reportSignatureCheck,
} from "#utils/check-report";
import type { ReportedVerification, SignatureState } from "#utils/commit-signature";
import { githubVerdict, inspectCommitSignature } from "#utils/commit-signature";
import { commitObjectId, commitPayload, signedCommitObject } from "#utils/git-commit";
import { GITHUB_API_ORIGIN } from "#utils/github-app";
import type { CheckRunInput, RepositoryClient } from "#utils/github-repo";
import { RepositoryClient as RepositoryClientClass } from "#utils/github-repo";
import { SIGNATURE_PREFIX } from "#utils/github-webhook";

const SECRET = "test-webhook-secret";
const INSTALLATION = 4242;
const APP_ID = 123456;
const REPOSITORY = "kjanat/service";
const KEY = "62E75E54497815DD";

/** A commit object's fields, fixed so every fixture differs only where it means to. */
const IDENTITY = { name: "Kaj Kowalski", email: "info@kajkowalski.nl", date: "2026-08-31T07:00:00Z", offset: "+0200" };
const TREE = "c93ec7f22ad2cabca76415f3389524a7d43c6435";
const PARENT = "cd01952d981ed9169dca0167e2a13b611db7de92";

function payloadFor(message: string): string {
	return commitPayload({ tree: TREE, parents: [PARENT], author: IDENTITY, committer: IDENTITY, message });
}

/** A real key, so the signatures under test are real signatures. */
async function generateKey(options: { date?: Date; keyExpirationTime?: number } = {}) {
	const { privateKey } = await openpgp.generateKey({
		type: "ecc",
		curve: "ed25519Legacy",
		userIDs: [{ name: "Check Report", email: "check@test.com" }],
		format: "armored",
		...options,
	});

	return {
		armoredPrivateKey: privateKey,
		publicKey: (await openpgp.readPrivateKey({ armoredKey: privateKey })).toPublic().armor(),
	};
}

/** Sign `payload` the way the service signs a commit: binary, detached, armored. */
async function sign(payload: string, armoredPrivateKey: string, date?: Date): Promise<string> {
	const stored = await openpgp.readPrivateKey({ armoredKey: armoredPrivateKey });
	const privateKey = stored.isDecrypted()
		? stored
		: await openpgp.decryptKey({ privateKey: stored, passphrase: env.KEY_PASSPHRASE });

	return (await openpgp.sign({
		message: await openpgp.createMessage({ binary: new TextEncoder().encode(payload) }),
		signingKeys: privateKey,
		detached: true,
		format: "armored",
		...(date === undefined ? {} : { date }),
	})) as string;
}

/**
 * A commit as a repository holds it: the object, and the sha Git names it by.
 *
 * The sha is computed over the assembled object rather than made up, so the
 * binding check in `inspectCommitSignature` is exercised against a real one.
 */
async function signedCommit(payload: string, signature: string) {
	return { sha: await commitObjectId(signedCommitObject(payload, signature)), payload, signature };
}

/** GitHub's verdict, set to whatever the fixture wants it to be. */
function reported(
	commit: { sha: string; payload: string | null; signature: string | null },
	verdict: { verified?: boolean; reason?: string | null } = {},
): ReportedVerification {
	return {
		sha: commit.sha,
		payload: commit.payload,
		signature: commit.signature,
		verified: verdict.verified ?? false,
		reason: verdict.reason ?? null,
	};
}

describe("what a commit's signature is allowed to prove", () => {
	let key: Awaited<ReturnType<typeof generateKey>>;
	let stranger: Awaited<ReturnType<typeof generateKey>>;

	beforeAll(async () => {
		key = await generateKey();
		stranger = await generateKey();
	});

	it("reports a commit with no signature as unsigned", async () => {
		const finding = await inspectCommitSignature(
			reported({ sha: "a".repeat(40), payload: null, signature: null }, { reason: "unsigned" }),
			key.publicKey,
		);

		expect(finding).toEqual({
			state: "unsigned",
			detail: "no_signature",
			github: { verified: false, reason: "unsigned" },
		});
	});

	it("treats an empty signature string as no signature", async () => {
		// A `verification.signature` of `""` is not a signature that failed to
		// parse; there is nothing there. Reading it as a malformed signature would
		// report an unsigned commit as broken.
		const finding = await inspectCommitSignature(
			reported({ sha: "a".repeat(40), payload: "x", signature: "   " }),
			key.publicKey,
		);

		expect(finding.state).toBe("unsigned");
	});

	it("attributes a signature by the bound key to the bound key", async () => {
		const payload = payloadFor("signed by us\n");
		const commit = await signedCommit(payload, await sign(payload, key.armoredPrivateKey));

		// GitHub says it is *not* verified — which is what it says for a key nobody
		// uploaded to a GitHub account, and is the common case for this service.
		// The finding is ours, so it disagrees.
		const finding = await inspectCommitSignature(
			reported(commit, { verified: false, reason: "unknown_key" }),
			key.publicKey,
		);

		expect(finding.state).toBe("service_key_valid");
		expect(finding.detail).toBe("verified");
		expect(finding.github).toEqual({ verified: false, reason: "unknown_key" });
	});

	it("makes no claim about a signature by somebody else's key", async () => {
		const payload = payloadFor("signed by a stranger\n");
		const commit = await signedCommit(payload, await sign(payload, stranger.armoredPrivateKey));

		// And GitHub says it *is* verified. A reporter that echoed GitHub would
		// call this ours.
		const finding = await inspectCommitSignature(reported(commit, { verified: true, reason: "valid" }), key.publicKey);

		expect(finding.state).toBe("other_signer");
		expect(finding.detail).toBe("different_key");
		expect(finding.github).toEqual({ verified: true, reason: "valid" });
	});

	it("makes no claim about an SSH signature", async () => {
		// Git signs with SSH keys too, and the armor is not PGP's. Somebody else's
		// signature in a format this service cannot check is `other_signer`, not a
		// broken signature.
		const payload = payloadFor("ssh signed\n");
		const signature = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ==\n-----END SSH SIGNATURE-----";
		const commit = await signedCommit(payload, signature);

		const finding = await inspectCommitSignature(reported(commit, { verified: true, reason: "valid" }), key.publicKey);

		expect(finding.state).toBe("other_signer");
		expect(finding.detail).toBe("non_pgp_signature");
	});

	it("reports a signature naming the bound key that does not verify as invalid", async () => {
		// The one alarming state. Built by signing one payload and folding that
		// signature into a *different* commit object — so the object id binds, the
		// key id is ours, and the signature is over bytes this commit does not
		// have. Which is exactly what a tampered commit looks like.
		const signed = payloadFor("the message that was signed\n");
		const actual = payloadFor("the message the commit holds\n");
		const signature = await sign(signed, key.armoredPrivateKey);
		const commit = await signedCommit(actual, signature);

		const finding = await inspectCommitSignature(
			reported(commit, { verified: false, reason: "invalid" }),
			key.publicKey,
		);

		expect(finding.state).toBe("invalid_signature");
		expect(finding.detail).toBe("verification_failed");
	});

	it("reports unreadable PGP armor as invalid", async () => {
		const payload = payloadFor("garbage armor\n");
		const signature = "-----BEGIN PGP SIGNATURE-----\n\nbm90IGEgc2lnbmF0dXJl\n-----END PGP SIGNATURE-----";
		const commit = await signedCommit(payload, signature);

		const finding = await inspectCommitSignature(reported(commit), key.publicKey);

		expect(finding.state).toBe("invalid_signature");
		expect(finding.detail).toBe("unreadable_signature");
	});

	it("claims nothing when the reported bytes are not this commit's", async () => {
		// The mutation this exists to catch: verify the signature against the
		// payload GitHub reported and report the result, without ever asking
		// whether that payload is the commit. Here it verifies perfectly — and
		// belongs to a different object id, so nothing has been shown about the
		// commit the ref points at.
		const payload = payloadFor("a genuinely signed commit\n");
		const signature = await sign(payload, key.armoredPrivateKey);

		const finding = await inspectCommitSignature(
			reported({ sha: `${"b".repeat(39)}0`, payload, signature }, { verified: true, reason: "valid" }),
			key.publicKey,
		);

		expect(finding.state).toBe("unverifiable");
		expect(finding.detail).toBe("object_binding_failed");
	});

	it("claims nothing when the reported payload is not a commit object at all", async () => {
		// A payload with no header boundary cannot be folded back into an object,
		// so the binding cannot be attempted — which is the same answer as a
		// binding that failed, and deliberately not a verdict about the signature.
		const payload = payloadFor("well formed\n");
		const signature = await sign(payload, key.armoredPrivateKey);

		const finding = await inspectCommitSignature(
			reported({ sha: "d".repeat(40), payload: "not a commit object", signature }),
			key.publicKey,
		);

		expect(finding).toMatchObject({ state: "unverifiable", detail: "object_binding_failed" });
	});

	it("refuses a signature that claims to have been made in the future", async () => {
		// The other half of the same pin. Verification happens at read time, so a
		// signature whose creation date is ahead of now is refused — which is why
		// no date is passed to `verify`: doing so with the signature's own
		// timestamp, the obvious way to make an expired key keep working, would
		// have made exactly this case start passing.
		const payload = payloadFor("from the future\n");
		const future = new Date(Date.now() + 24 * 60 * 60 * 1000);
		const commit = await signedCommit(payload, await sign(payload, key.armoredPrivateKey, future));

		const finding = await inspectCommitSignature(reported(commit), key.publicKey);

		expect(finding.state).toBe("invalid_signature");
	});

	it("claims nothing when a signature arrives with no payload", async () => {
		const payload = payloadFor("no payload reported\n");
		const signature = await sign(payload, key.armoredPrivateKey);

		const finding = await inspectCommitSignature(
			reported({ sha: "c".repeat(40), payload: null, signature }),
			key.publicKey,
		);

		expect(finding.state).toBe("unverifiable");
		expect(finding.detail).toBe("no_payload");
	});

	it("claims nothing when the bound key's own material will not parse", async () => {
		const payload = payloadFor("unreadable key\n");
		const commit = await signedCommit(payload, await sign(payload, key.armoredPrivateKey));

		const finding = await inspectCommitSignature(reported(commit), "-----BEGIN PGP PUBLIC KEY BLOCK-----\nnope\n");

		expect(finding.state).toBe("unverifiable");
		expect(finding.detail).toBe("unreadable_service_key");
	});

	it("attributes a signature made by a signing subkey to the key that holds it", async () => {
		// The reason the comparison is against the key's own ids rather than the
		// configured id string: an OpenPGP key signs with its signing subkey, whose
		// id is not the primary's. A GnuPG-generated key almost always has one, so
		// comparing against the allowlist's 16 hex digits would report this
		// service's own signatures as somebody else's.
		const rsa = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Subkey", email: "subkey@test.com" }],
			subkeys: [{ sign: true }],
			format: "armored",
		});
		const parsed = await openpgp.readPrivateKey({ armoredKey: rsa.privateKey });
		const primary = parsed.getKeyID().toHex().toUpperCase();
		const signingKey = await parsed.getSigningKey();

		expect(signingKey.getKeyID().toHex().toUpperCase()).not.toBe(primary);

		const payload = payloadFor("signed by a subkey\n");
		const commit = await signedCommit(payload, await sign(payload, rsa.privateKey));

		const finding = await inspectCommitSignature(reported(commit), parsed.toPublic().armor());

		expect(finding.state).toBe("service_key_valid");
	});

	it("still attributes a signature made before its key expired", async () => {
		// A characterization test, and labelled as one because the property is
		// openpgp.js's rather than this module's: `verify` looks a key up by id and
		// does not gate on expiry, so a signature made while a key was live still
		// verifies after it expires. That is the answer this service wants — the
		// alternative flips every commit a key ever signed to `invalid_signature`,
		// an accusation of forgery, on the day it expires — and it is pinned here
		// so a change in those semantics is a failing test rather than a silent
		// change of verdict on every historical commit.
		const created = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
		const expiring = await generateKey({ date: created, keyExpirationTime: 60 * 60 });
		const signedAt = new Date(created.getTime() + 60 * 1000);

		const payload = payloadFor("signed while the key was live\n");
		const commit = await signedCommit(payload, await sign(payload, expiring.armoredPrivateKey, signedAt));

		const finding = await inspectCommitSignature(reported(commit), expiring.publicKey);

		expect(finding.state).toBe("service_key_valid");
	});
});

describe("GitHub's own verdict, repeated rather than adopted", () => {
	it("passes through a reason GitHub documents", () => {
		expect(githubVerdict(true, "valid")).toEqual({ verified: true, reason: "valid" });
	});

	it.each([
		["prose", "Signature made by <script>alert(1)</script>"],
		["markdown that would break out of the summary", "```\n# Verified\n"],
		["a value from some future API version", "brand_new_reason"],
		["a non-string", 42],
		["null", null],
	])("replaces %s with `unknown`", (_case, reason) => {
		// This string is published under this service's name in a check run. A
		// remote API does not get to choose it.
		expect(githubVerdict(false, reason).reason).toBe("unknown");
	});

	it("reads anything but the literal true as not verified", () => {
		expect(githubVerdict("true", "valid").verified).toBe(false);
		expect(githubVerdict(1, "valid").verified).toBe(false);
	});
});

describe("the conclusion each state earns", () => {
	it.each([
		["service_key_valid", "success"],
		["invalid_signature", "failure"],
		["unsigned", "neutral"],
		["other_signer", "neutral"],
		["unverifiable", "neutral"],
	])("maps %s to %s", (state, conclusion) => {
		expect(conclusionFor(state as SignatureState)).toBe(conclusion);
	});

	it("fails a commit only for a signature that claims our key and does not verify", () => {
		// The states this service has no standing to fail a commit over: an
		// unsigned commit beneath a signed one stays unsigned by design, and
		// somebody else's signature is somebody else's business. A reporter that
		// failed those would make the check unusable and say more than it knows.
		const failing = (
			["unsigned", "other_signer", "unverifiable", "service_key_valid", "invalid_signature"] as const
		).filter((state) => conclusionFor(state) === "failure");

		expect(failing).toEqual(["invalid_signature"]);
	});
});

describe("what the check run body may contain", () => {
	it("carries no signature, no payload and no key material", async () => {
		const key = await generateKey();
		const payload = payloadFor("a summary is published text\n");
		const signature = await sign(payload, key.armoredPrivateKey);
		const commit = await signedCommit(payload, signature);
		const finding = await inspectCommitSignature(reported(commit, { verified: true, reason: "valid" }), key.publicKey);

		const summary = checkRunSummary(commit.sha, KEY, finding);

		expect(summary).not.toContain("BEGIN PGP");
		expect(summary).not.toContain(signature.slice(40, 80));
		expect(summary).not.toContain(payload);
		expect(summary).not.toContain(key.armoredPrivateKey.slice(40, 80));
		// And it does carry the things an operator reads it for.
		expect(summary).toContain(commit.sha);
		expect(summary).toContain(KEY);
		expect(summary).toContain("service_key_valid");
	});

	it.each([
		["service_key_valid", "verified", "verifies over the commit's own bytes"],
		["invalid_signature", "verification_failed", "does not verify under it"],
		["other_signer", "different_key", "No claim is made"],
		["unsigned", "no_signature", "carries no signature"],
		["unverifiable", "object_binding_failed", "could not be tied back"],
	])("says what %s means without overstating it", (state, detail, expected) => {
		const summary = checkRunSummary("d".repeat(40), KEY, {
			state: state as SignatureState,
			detail: detail as never,
			github: githubVerdict(false, "unsigned"),
		});

		expect(summary).toContain(expected);
		expect(summary).toContain(state);
	});

	it("never repeats a GitHub reason it does not recognise", () => {
		const summary = checkRunSummary("a".repeat(40), KEY, {
			state: "other_signer",
			detail: "different_key",
			github: githubVerdict(true, "</details><img src=x onerror=alert(1)>"),
		});

		expect(summary).not.toContain("onerror");
		expect(summary).toContain("unknown");
	});
});

/** A `RepositoryClient` that records what it was asked to do. */
function fakeClient(options: {
	ref?: { ref: string; sha: string } | null;
	verification?: Partial<ReportedVerification>;
	existing?: { id: number }[];
	listThrows?: boolean;
	createThrows?: boolean;
	updateThrows?: boolean;
	createReturns?: number;
}) {
	const calls: string[] = [];
	const written: CheckRunInput[] = [];
	const sha = options.ref === undefined ? "1".repeat(40) : (options.ref?.sha ?? "");

	const client = {
		repository: REPOSITORY,
		getBranch: (branch: string) => {
			calls.push(`getBranch:${branch}`);
			return Promise.resolve(options.ref === null ? null : { ref: `refs/heads/${branch}`, sha });
		},
		getCommitVerification: (asked: string) => {
			calls.push(`getCommitVerification:${asked}`);
			return Promise.resolve({
				sha: asked,
				signature: null,
				payload: null,
				verified: false,
				reason: null,
				...options.verification,
			});
		},
		listCheckRuns: (asked: string, name: string, appId: number) => {
			calls.push(`listCheckRuns:${asked}:${name}:${appId}`);
			if (options.listThrows) {
				throw new Error("GitHub refused a check run lookup for kjanat/service");
			}
			return Promise.resolve(options.existing ?? []);
		},
		createCheckRun: (input: CheckRunInput) => {
			calls.push(`createCheckRun:${input.headSha}`);
			if (options.createThrows) {
				throw new Error("GitHub refused a check run creation for kjanat/service");
			}
			written.push(input);
			return Promise.resolve(options.createReturns ?? 7);
		},
		updateCheckRun: (id: number, input: CheckRunInput) => {
			calls.push(`updateCheckRun:${id}`);
			if (options.updateThrows) {
				throw new Error("GitHub refused a check run update for kjanat/service");
			}
			written.push(input);
			return Promise.resolve();
		},
	};

	return { client: client as unknown as RepositoryClient, calls, written };
}

const ON = { GITHUB_APP_CHECK_RUNS: "true", GITHUB_APP_ID: String(APP_ID) };

describe("publishing the report", () => {
	let key: Awaited<ReturnType<typeof generateKey>>;
	let stored: never;

	beforeAll(async () => {
		key = await generateKey();
		stored = {
			keyId: KEY,
			armoredPrivateKey: key.armoredPrivateKey,
			algorithm: "eddsa",
			fingerprint: "f".repeat(40),
			createdAt: new Date().toISOString(),
		} as never;
	});

	it("makes no GitHub call at all when the feature is off", async () => {
		const { client, calls } = fakeClient({});

		const result = await reportSignatureCheck({ GITHUB_APP_ID: String(APP_ID) }, client, "main", stored, KEY);

		expect(result).toEqual({ outcome: "skipped", reason: "disabled" });
		expect(calls).toHaveLength(0);
	});

	it.each([["1"], ["TRUE"], ["yes"], ["True"], [""], [undefined]])(
		"stays off for GITHUB_APP_CHECK_RUNS=%s",
		async (value) => {
			// One spelling, the same rule `githubAppEnabled` uses. A flag that
			// accepted near-misses would turn a typo into calls an installation never
			// granted.
			expect(checkRunsEnabled(value === undefined ? {} : { GITHUB_APP_CHECK_RUNS: value })).toBe(false);
		},
	);

	it("publishes nothing when the App id is not a number", async () => {
		// Without it, this App's own check runs cannot be told from another app's,
		// so the lookup that makes the write converge cannot be trusted — and a
		// create on top of that is how duplicates start.
		const { client, calls } = fakeClient({});

		const result = await reportSignatureCheck(
			{ GITHUB_APP_CHECK_RUNS: "true", GITHUB_APP_ID: "not-a-number" },
			client,
			"main",
			stored,
			KEY,
		);

		expect(result).toEqual({ outcome: "skipped", reason: "app_id_unusable" });
		expect(calls).toHaveLength(0);
	});

	it("publishes nothing for an X.509 key", async () => {
		const { client, calls } = fakeClient({});
		const x509 = { type: "x509", keyId: KEY, privateKeyPem: "x", certificatePem: "y", createdAt: "" } as never;

		const result = await reportSignatureCheck(ON, client, "main", x509, KEY);

		expect(result).toEqual({ outcome: "skipped", reason: "unsupported_key" });
		expect(calls).toHaveLength(0);
	});

	it("publishes nothing when the branch is gone", async () => {
		const { client, calls } = fakeClient({ ref: null });

		const result = await reportSignatureCheck(ON, client, "main", stored, KEY);

		expect(result).toEqual({ outcome: "skipped", reason: "branch_missing" });
		expect(calls.some((call) => call.startsWith("createCheckRun"))).toBe(false);
	});

	it.each([
		["an abbreviated one", "1234567"],
		["upper case", "A".repeat(40)],
		["something that is not hex at all", "../../../etc/passwd"],
		["a value carrying markdown", "`a`](https://evil.example)"],
	])("publishes nothing when the ref names %s", async (_case, sha) => {
		// The sha reaches a URL path and a published markdown summary. A response
		// that does not carry a commit id is refused rather than rendered.
		const { client, calls } = fakeClient({ ref: { ref: "refs/heads/main", sha } });

		const result = await reportSignatureCheck(ON, client, "main", stored, KEY);

		expect(result).toEqual({ outcome: "skipped", reason: "unusable_sha" });
		expect(calls.some((call) => call.startsWith("createCheckRun"))).toBe(false);
	});

	it("publishes nothing when GitHub answers about a different commit", async () => {
		const { client, calls } = fakeClient({ verification: { sha: "9".repeat(40) } });

		const result = await reportSignatureCheck(ON, client, "main", stored, KEY);

		expect(result).toEqual({ outcome: "skipped", reason: "unusable_sha" });
		expect(calls.some((call) => call.startsWith("createCheckRun"))).toBe(false);
	});

	it("creates a run for the sha the ref holds, under the constant name", async () => {
		const { client, calls, written } = fakeClient({});

		const result = await reportSignatureCheck(ON, client, "main", stored, KEY);

		expect(result.outcome).toBe("published");
		expect(calls).toContain(`listCheckRuns:${"1".repeat(40)}:${CHECK_RUN_NAME}:${APP_ID}`);
		expect(written).toHaveLength(1);
		expect(written[0]?.headSha).toBe("1".repeat(40));
		expect(written[0]?.name).toBe(CHECK_RUN_NAME);
		expect(written[0]?.conclusion).toBe("neutral");
	});

	it("updates the run that already exists rather than adding another", async () => {
		// The lost-response case, and the redelivery case, and the second event
		// about the same head: all three are this.
		const { client, calls } = fakeClient({ existing: [{ id: 41 }] });

		const result = await reportSignatureCheck(ON, client, "main", stored, KEY);

		expect(result).toMatchObject({ outcome: "published", checkRunId: 41, action: "updated" });
		expect(calls.some((call) => call.startsWith("createCheckRun"))).toBe(false);
	});

	it("converges on the earliest run when a race left two", async () => {
		// Not "the first the API happened to return". Two callers reaching the same
		// answer independently is what makes convergence a property rather than an
		// accident of ordering.
		const { client } = fakeClient({ existing: [{ id: 12 }, { id: 99 }] });

		const result = await reportSignatureCheck(ON, client, "main", stored, KEY);

		expect(result).toMatchObject({ checkRunId: 12, action: "updated" });
	});

	it("reports a failure when the lookup fails, and publishes nothing", async () => {
		const { client, calls } = fakeClient({ listThrows: true });

		const result = await reportSignatureCheck(ON, client, "main", stored, KEY);

		expect(result.outcome).toBe("failed");
		expect(calls.some((call) => call.startsWith("createCheckRun"))).toBe(false);
	});

	it("reports a failure when the create fails", async () => {
		// An installation that has not granted `checks: write` lands here on every
		// delivery, with a 403.
		const { client } = fakeClient({ createThrows: true });

		const result = await reportSignatureCheck(ON, client, "main", stored, KEY);

		expect(result).toMatchObject({ outcome: "failed" });
		expect(result.outcome === "failed" && result.reason).toContain("check run creation");
	});

	it("reports a failure when the update fails", async () => {
		const { client } = fakeClient({ existing: [{ id: 3 }], updateThrows: true });

		const result = await reportSignatureCheck(ON, client, "main", stored, KEY);

		expect(result.outcome).toBe("failed");
	});
});

describe("the Checks API on the repository-scoped client", () => {
	beforeAll(async () => {
		APP_PRIVATE_KEY ||= await generateAppKey();
	});

	beforeEach(() => {
		vi.restoreAllMocks();
	});

	/** The real client, bound to the authorized pair, with `fetch` stubbed. */
	function realClient(respond: (request: Request, url: URL) => Response | Promise<Response>) {
		const seen: Request[] = [];
		vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
			const request = new Request(input as RequestInfo, init as RequestInit);
			const url = new URL(request.url);
			seen.push(request);

			if (url.pathname.endsWith("/access_tokens")) {
				return Promise.resolve(
					Response.json(
						{ token: "ghs_secret", expires_at: new Date(Date.now() + 3600_000).toISOString() },
						{ status: 201 },
					),
				);
			}

			return Promise.resolve(respond(request, url));
		});

		const client = RepositoryClientClass.forAuthorization(
			{ ...env, GITHUB_APP_ID: String(APP_ID), GITHUB_APP_PRIVATE_KEY: APP_PRIVATE_KEY } as never,
			{ scope: "repository", installationId: 7777, repository: REPOSITORY, keyId: KEY },
		);

		return { client: client as RepositoryClient, seen };
	}

	it("returns only this App's runs under this name, earliest first", async () => {
		const { client, seen } = realClient(() =>
			Response.json({
				check_runs: [
					{ id: 90, name: CHECK_RUN_NAME, app: { id: APP_ID } },
					{ id: 12, name: CHECK_RUN_NAME, app: { id: APP_ID } },
					{ id: 3, name: CHECK_RUN_NAME, app: { id: 999 } },
					{ id: 4, name: "Another check", app: { id: APP_ID } },
					{ id: 5, name: CHECK_RUN_NAME, app: null },
				],
			}),
		);

		const runs = await client.listCheckRuns("f".repeat(40), CHECK_RUN_NAME, APP_ID);

		expect(runs).toEqual([{ id: 12 }, { id: 90 }]);
		// The name is a query filter as well as a local one; GitHub's filter is not
		// trusted to be the only thing that narrows the list.
		expect(seen.at(-1)?.url).toContain(`check_name=${encodeURIComponent(CHECK_RUN_NAME)}`);
	});

	it("sends head_sha when creating and never when updating", async () => {
		// A run's commit is not editable, and an update that carried one would be
		// the one call able to move a published verdict onto another commit.
		const bodies: Record<string, unknown>[] = [];
		const { client } = realClient(async (request) => {
			bodies.push((await request.json()) as Record<string, unknown>);
			return Response.json({ id: 1, name: CHECK_RUN_NAME }, { status: 201 });
		});

		const input = {
			name: CHECK_RUN_NAME,
			headSha: "a".repeat(40),
			conclusion: "success" as const,
			title: "t",
			summary: "s",
			completedAt: new Date().toISOString(),
		};

		await client.createCheckRun(input);
		await client.updateCheckRun(1, input);

		expect(bodies[0]?.head_sha).toBe("a".repeat(40));
		expect(bodies[1]).not.toHaveProperty("head_sha");
		expect(bodies[1]?.conclusion).toBe("success");
	});

	it("raises an error carrying a status and none of GitHub's body", async () => {
		// The body of a GitHub error can quote back the request that produced it,
		// and that request carried an installation token.
		const { client } = realClient(() =>
			Response.json({ message: "Resource not accessible by integration", token_hint: "ghs_secret" }, { status: 403 }),
		);

		const failure = (await client
			.updateCheckRun(1, {
				name: CHECK_RUN_NAME,
				headSha: "a".repeat(40),
				conclusion: "neutral",
				title: "t",
				summary: "s",
				completedAt: new Date().toISOString(),
			})
			.catch((error: unknown) => error)) as Error;

		expect(failure).toBeInstanceOf(Error);
		expect(failure.message).toBe(`GitHub refused a check run update for ${REPOSITORY}`);
		expect(failure.message).not.toContain("ghs_secret");
		expect(failure.message).not.toContain("not accessible");
	});
});

/** A real RSA key for the App, so the token exchange mints a real JWT. */
let APP_PRIVATE_KEY = "";

async function generateAppKey(): Promise<string> {
	const pair = (await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	const der = new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer);
	let binary = "";
	for (const byte of der) {
		binary += String.fromCharCode(byte);
	}

	return `-----BEGIN PRIVATE KEY-----\n${btoa(binary).replace(/(.{64})/g, "$1\n")}\n-----END PRIVATE KEY-----\n`;
}

async function hmac(body: string): Promise<string> {
	const signingKey = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(SECRET),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const mac = new Uint8Array(await crypto.subtle.sign("HMAC", signingKey, new TextEncoder().encode(body)));

	return SIGNATURE_PREFIX + [...mac].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

describe("through the endpoint", () => {
	/** The head the branch really points at: signed, so nothing is rewritten. */
	let HEAD_SHA = "";
	let HEAD_PAYLOAD = "";
	let HEAD_SIGNATURE = "";

	beforeAll(async () => {
		APP_PRIVATE_KEY = await generateAppKey();

		// The audit table with the constraint migration 0006 leaves behind. Written
		// out rather than relaxed to TEXT, so an insert of `check_report` is checked
		// against the same closed set production checks it against — a migration
		// that forgot the value fails here rather than in D1.
		for (const statement of [
			`CREATE TABLE IF NOT EXISTS audit_logs (
				id TEXT PRIMARY KEY,
				timestamp TEXT NOT NULL,
				request_id TEXT NOT NULL,
				action TEXT NOT NULL CHECK (action IN (
					'sign', 'key_upload', 'key_rotate', 'token_create', 'token_revoke',
					'subject_create', 'subject_revoke', 'push_sign', 'check_report'
				)),
				issuer TEXT NOT NULL,
				subject TEXT NOT NULL,
				key_id TEXT NOT NULL,
				success INTEGER NOT NULL DEFAULT 0,
				error_code TEXT,
				metadata TEXT
			)`,
			"CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs (action)",
		]) {
			await env.AUDIT_DB.prepare(statement).run();
		}

		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Check Report", email: "check@test.com" }],
			passphrase: env.KEY_PASSPHRASE,
			format: "armored",
		});

		const ctx = createExecutionContext();
		const upload = await app.fetch(
			new Request("https://sign.test/admin/keys", {
				method: "POST",
				headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}`, "Content-Type": "application/json" },
				body: JSON.stringify({ armoredPrivateKey: privateKey, keyId: KEY }),
			}),
			env,
			ctx,
		);
		await waitOnExecutionContext(ctx);
		expect(upload.status).toBe(201);

		HEAD_PAYLOAD = payloadFor("already signed\n");
		HEAD_SIGNATURE = await sign(HEAD_PAYLOAD, privateKey);
		HEAD_SHA = await commitObjectId(signedCommitObject(HEAD_PAYLOAD, HEAD_SIGNATURE));
	});

	beforeEach(() => {
		vi.restoreAllMocks();
	});

	/**
	 * A `fetch` stub that behaves like GitHub for one branch whose head is signed.
	 *
	 * Anything off `api.github.com` throws, so destination pinning is enforced by
	 * the stub rather than by an assertion somebody could forget to write, and
	 * every path is recorded so the repository and installation a call was made
	 * *for* can be asserted rather than assumed.
	 */
	function stubGitHub(
		options: {
			existing?: { id: number; name?: string; appId?: number | null }[];
			checksForbidden?: boolean;
			createLosesResponse?: boolean;
			refMissing?: boolean;
		} = {},
	) {
		const calls: { method: string; path: string; body: Record<string, unknown> | undefined }[] = [];
		let nextId = 100;
		const runs = [...(options.existing ?? [])];

		vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
			const request = new Request(input as RequestInfo, init as RequestInit);
			const url = new URL(request.url);

			if (url.origin !== GITHUB_API_ORIGIN) {
				throw new Error(`off the pinned origin: ${url.origin}`);
			}

			// A token exchange is a POST with no body at all, so this cannot assume
			// one is there to read.
			let body: Record<string, unknown> | undefined;
			try {
				body = request.method === "GET" ? undefined : ((await request.json()) as Record<string, unknown>);
			} catch {
				body = undefined;
			}
			calls.push({ method: request.method, path: url.pathname, body });

			if (url.pathname.endsWith("/access_tokens")) {
				return Response.json(
					{ token: "ghs_secret", expires_at: new Date(Date.now() + 3600_000).toISOString() },
					{ status: 201 },
				);
			}

			if (url.pathname.includes("/git/ref/heads/")) {
				if (options.refMissing) {
					return Response.json({ message: "Not Found" }, { status: 404 });
				}
				return Response.json({ ref: "refs/heads/main", object: { sha: HEAD_SHA } });
			}

			if (url.pathname.includes("/git/commits/")) {
				return Response.json({
					sha: HEAD_SHA,
					message: "already signed",
					tree: { sha: TREE },
					parents: [{ sha: PARENT }],
					author: { name: IDENTITY.name, email: IDENTITY.email, date: IDENTITY.date },
					committer: { name: IDENTITY.name, email: IDENTITY.email, date: IDENTITY.date },
					verification: { verified: false, reason: "unknown_key", signature: HEAD_SIGNATURE, payload: HEAD_PAYLOAD },
				});
			}

			if (url.pathname.endsWith("/check-runs") && request.method === "GET") {
				return Response.json({
					check_runs: runs.map((run) => ({
						id: run.id,
						name: run.name ?? CHECK_RUN_NAME,
						app: run.appId === null ? null : { id: run.appId ?? APP_ID },
					})),
				});
			}

			if (url.pathname.endsWith("/check-runs") && request.method === "POST") {
				if (options.checksForbidden) {
					return Response.json({ message: "Resource not accessible by integration" }, { status: 403 });
				}
				const id = nextId++;
				// The run is created whether or not the caller ever learns it was.
				runs.push({ id });
				if (options.createLosesResponse) {
					throw new Error("network dropped the response");
				}
				return Response.json({ id, name: CHECK_RUN_NAME }, { status: 201 });
			}

			if (url.pathname.includes("/check-runs/") && request.method === "PATCH") {
				return Response.json({ id: Number(url.pathname.split("/").pop()), name: CHECK_RUN_NAME });
			}

			throw new Error(`unexpected path ${url.pathname}`);
		});

		return { calls, runs };
	}

	function pushPayload(installationId: number, repository: string) {
		return {
			ref: "refs/heads/main",
			deleted: false,
			before: "0".repeat(40),
			// A sha the branch does not point at. A reporter that took the head from
			// the payload would attach the check run to this one.
			after: "e".repeat(40),
			installation: { id: installationId },
			repository: { full_name: repository, name: repository.split("/")[1] },
		};
	}

	async function deliver(options: {
		allowlist: string;
		deliveryId?: string;
		checkRuns?: string;
		payload?: unknown;
	}): Promise<{ response: Response; body: Record<string, unknown> }> {
		const body = JSON.stringify(options.payload ?? pushPayload(INSTALLATION, REPOSITORY));
		const ctx = createExecutionContext();
		const response = await app.fetch(
			new Request("https://sign.test/github/webhook", {
				method: "POST",
				body,
				headers: {
					"Content-Type": "application/json",
					"X-Hub-Signature-256": await hmac(body),
					"X-GitHub-Event": "push",
					"X-GitHub-Delivery": options.deliveryId ?? crypto.randomUUID(),
				},
			}),
			{
				...env,
				GITHUB_APP_ENABLED: "true",
				GITHUB_WEBHOOK_SECRET: SECRET,
				GITHUB_APP_ALLOWED_REPOSITORIES: options.allowlist,
				GITHUB_APP_ID: String(APP_ID),
				GITHUB_APP_PRIVATE_KEY: APP_PRIVATE_KEY,
				GITHUB_APP_CHECK_RUNS: options.checkRuns ?? "true",
			},
			ctx,
		);
		await waitOnExecutionContext(ctx);

		return { response, body: (await response.json()) as Record<string, unknown> };
	}

	it("reaches no Checks API path at all with the flag off", async () => {
		// The shipped default. A deployment that has not opted in behaves exactly
		// as it did before this existed — which is what makes "#132 is preserved"
		// a property rather than a claim.
		const { calls } = stubGitHub();

		const { response, body } = await deliver({
			allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}`,
			checkRuns: "false",
		});

		expect(response.status).toBe(202);
		expect(body.skipped).toBe("nothing_to_sign");
		expect(body.check).toBeUndefined();
		expect(calls.some((call) => call.path.includes("check-runs"))).toBe(false);
	});

	it("publishes a check for the sha the ref holds, not the one the payload claims", async () => {
		const { calls } = stubGitHub();

		const { response, body } = await deliver({ allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}` });

		expect(response.status).toBe(202);
		expect(body.check).toBe("service_key_valid");

		const created = calls.find((call) => call.method === "POST" && call.path.endsWith("/check-runs"));
		expect(created?.body?.head_sha).toBe(HEAD_SHA);
		expect(created?.body?.head_sha).not.toBe("e".repeat(40));
		expect(created?.body?.name).toBe(CHECK_RUN_NAME);
		expect(created?.body?.conclusion).toBe("success");
	});

	it("makes every Checks API call under the authorized repository and installation", async () => {
		// Cross-repository and cross-installation confusion, at the reporting path.
		// The payload's spelling of the repository differs in case from the
		// allowlist's, so a reporter that used `payload.repository.full_name` would
		// address a different path.
		// A distinct installation, so the token exchange is not answered out of the
		// KV cache another test in this file filled — the token path is half of
		// what this test is asserting.
		const installation = INSTALLATION + 1;
		const { calls } = stubGitHub();

		await deliver({
			allowlist: `${installation}:${REPOSITORY}=${KEY}`,
			payload: pushPayload(installation, "KJANAT/SERVICE"),
		});

		const checkPaths = calls.filter((call) => call.path.includes("check-runs"));
		expect(checkPaths.length).toBeGreaterThan(0);
		for (const call of checkPaths) {
			expect(call.path.startsWith(`/repos/${REPOSITORY}/`)).toBe(true);
		}

		const tokens = calls.filter((call) => call.path.endsWith("/access_tokens"));
		expect(tokens.length).toBeGreaterThan(0);
		for (const call of tokens) {
			expect(call.path).toBe(`/app/installations/${installation}/access_tokens`);
		}
	});

	it("updates one run instead of creating a second when the same head is reported again", async () => {
		// Two distinct deliveries about the same head — the shape a redelivery
		// under a fresh id, or a second push landing on the same commit, produces.
		const { calls } = stubGitHub();
		const allowlist = `${INSTALLATION}:${REPOSITORY}=${KEY}`;

		await deliver({ allowlist });
		await deliver({ allowlist });

		expect(calls.filter((call) => call.method === "POST" && call.path.endsWith("/check-runs"))).toHaveLength(1);
		expect(calls.filter((call) => call.method === "PATCH")).toHaveLength(1);
	});

	it("updates rather than duplicating after a create whose response was lost", async () => {
		// The unsafe second effect this design exists to prevent: the run *was*
		// created, and the caller never learnt its id. A second attempt finds it.
		const allowlist = `${INSTALLATION}:${REPOSITORY}=${KEY}`;
		const lost = stubGitHub({ createLosesResponse: true });

		const first = await deliver({ allowlist });
		expect(first.body.check).toBeUndefined();
		expect(lost.runs).toHaveLength(1);

		const { calls } = stubGitHub({ existing: lost.runs });
		const second = await deliver({ allowlist });

		expect(second.body.check).toBe("service_key_valid");
		expect(calls.filter((call) => call.method === "POST" && call.path.endsWith("/check-runs"))).toHaveLength(0);
		expect(calls.filter((call) => call.method === "PATCH")).toHaveLength(1);
	});

	it("creates its own run beside another app's with the same name", async () => {
		// `check_name` is not unique across apps, and a PATCH on somebody else's
		// run is refused by GitHub — so a reporter that took the first match would
		// fail on a repository that happens to run another signature check.
		const { calls } = stubGitHub({
			existing: [
				{ id: 5, appId: 999 },
				{ id: 6, appId: null },
			],
		});

		await deliver({ allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}` });

		expect(calls.filter((call) => call.method === "POST" && call.path.endsWith("/check-runs"))).toHaveLength(1);
		expect(calls.filter((call) => call.method === "PATCH")).toHaveLength(0);
	});

	it("ignores a run of ours under a different name", async () => {
		const { calls } = stubGitHub({ existing: [{ id: 8, name: "Some other check" }] });

		await deliver({ allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}` });

		expect(calls.filter((call) => call.method === "POST" && call.path.endsWith("/check-runs"))).toHaveLength(1);
	});

	it("publishes no check when the branch is gone by the time it looks", async () => {
		// The delivery is about a branch that no longer exists — deleted between
		// the push and this request. There is no head, so there is nothing to
		// report on, and nothing is written.
		const { calls } = stubGitHub({ refMissing: true });

		const { body } = await deliver({ allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}` });

		expect(body.skipped).toBe("branch_missing");
		expect(body.check).toBeUndefined();
		expect(calls.some((call) => call.path.includes("check-runs"))).toBe(false);
	});

	it("publishes no check for a repository the allowlist bound no key to", async () => {
		// Receiving events and causing signatures are separate grants, and so are
		// receiving events and having a key to attribute a signature to.
		const { calls } = stubGitHub();

		const { body } = await deliver({ allowlist: `${INSTALLATION}:${REPOSITORY}` });

		expect(body.skipped).toBe("no_key_bound");
		expect(calls).toHaveLength(0);
	});

	it("leaves the delivery committed when the check cannot be published", async () => {
		// A reporting failure must not make a *signing* delivery retryable. The
		// assertion is the redelivery: a committed id comes back `duplicate: true`.
		const id = crypto.randomUUID();
		const allowlist = `${INSTALLATION}:${REPOSITORY}=${KEY}`;
		stubGitHub({ checksForbidden: true });

		const first = await deliver({ allowlist, deliveryId: id });
		expect(first.response.status).toBe(202);
		expect(first.body.skipped).toBe("nothing_to_sign");
		expect(first.body.check).toBeUndefined();

		const second = await deliver({ allowlist, deliveryId: id });
		expect(second.body.duplicate).toBe(true);
	});

	it("records what it published, with no signature or token in the row", async () => {
		stubGitHub();

		await deliver({ allowlist: `${INSTALLATION}:${REPOSITORY}=${KEY}` });

		const row = await env.AUDIT_DB.prepare(
			"SELECT action, issuer, subject, key_id, success, metadata FROM audit_logs WHERE action = 'check_report' ORDER BY rowid DESC LIMIT 1",
		).first<{ subject: string; key_id: string; success: number; metadata: string }>();

		expect(row?.subject).toBe(REPOSITORY);
		expect(row?.key_id).toBe(KEY);
		expect(row?.success).toBe(1);

		const metadata = JSON.parse(row?.metadata ?? "{}") as Record<string, unknown>;
		expect(metadata).toMatchObject({ sha: HEAD_SHA, state: "service_key_valid", conclusion: "success" });
		expect(row?.metadata).not.toContain("BEGIN PGP");
		expect(row?.metadata).not.toContain("ghs_secret");
	});
});
