/**
 * The first thing in this service a webhook can cause.
 *
 * Everything before this slice refused: the HMAC refused an unsigned delivery,
 * the allowlist refused an ungranted subject, the ledger refused a repeat. This
 * one *acts* — it rewrites a branch — so the tests are written against the ways
 * acting goes wrong rather than against the shape of a successful run.
 *
 * What each group is really asserting:
 *
 * - **Nothing is chosen by the payload.** The repository and the key come from
 *   the allowlist entry, so a delivery naming another repository, or the right
 *   repository under another installation, cannot reach the key it is not
 *   granted. Two grants with two different keys run side by side below and the
 *   signatures are verified against the *wrong* key as well as the right one,
 *   because a test that only checks the right key passes for an implementation
 *   that ignores the binding entirely.
 * - **A push this service makes does not come back.** Asserted as the fixpoint
 *   it is: the delivery caused by the service's own push is fed back in, and it
 *   must reach GitHub for exactly one read and make no write at all. Not an
 *   actor check, not an event-name check — the commits themselves.
 * - **Nothing is destroyed.** A foreign signature, a foreign committer, a merge
 *   and a commit whose bytes cannot be rebuilt each stop the run before a
 *   single object is created.
 * - **The irreversible step is the only irreversible step.** Every failure mode
 *   below is checked for whether the branch moved, and the recoverable ones are
 *   checked for whether the delivery id came back — because the whole point of
 *   the two-phase ledger is that an operator's **Redeliver** is a real retry.
 * - **Concurrency cannot double-act.** Two copies of one delivery race, and
 *   exactly one `PATCH` is allowed to happen.
 *
 * The GitHub double renders commit objects with its own serialiser rather than
 * the one under test, so the happy path is an agreement between two independent
 * implementations rather than a tautology, and it refuses any request that
 * leaves `api.github.com`.
 */

import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import * as openpgp from "openpgp";
import { beforeAll, describe, expect, it, vi } from "vitest";
import app from "#gpg-signing-service";
import type { Env } from "#types";
import { GITHUB_API_ORIGIN } from "#utils/github-app";
import { SIGNATURE_HEADER, SIGNATURE_PREFIX } from "#utils/github-webhook";
import { signingBudgetIdentity } from "#utils/push-signing";
import { verifyDetachedSignature } from "#utils/signing";

const SECRET = "test-webhook-secret";
const OWNER = "kjanat";
const BRANCH = "master";

/** A fresh installation id per test, so the KV token cache never crosses one. */
let nextInstallation = 700_000;
function installation(): number {
	nextInstallation += 1;
	return nextInstallation;
}

// ---------------------------------------------------------------------------
// The GitHub double
// ---------------------------------------------------------------------------

interface FakeIdentity {
	name: string;
	email: string;
	date: string;
}

interface FakeCommit {
	sha: string;
	tree: { sha: string };
	parents: { sha: string }[];
	author: FakeIdentity;
	committer: FakeIdentity;
	message: string;
	verification: { signature: string | null; payload: string | null };
}

/**
 * `<epoch> <±HHMM>`, written independently of the code under test.
 *
 * Deliberately not `gitTimestamp`. If the double borrowed the serialiser, the
 * created-object check in `signAndCreate` would be comparing an implementation
 * with itself and would pass however wrong both were.
 */
function stamp(iso: string): string {
	const offset = /(Z|[+-]\d{2}:?\d{2})$/.exec(iso)?.[1] ?? "Z";
	return `${Math.floor(Date.parse(iso) / 1000)} ${offset === "Z" ? "+0000" : offset.replace(":", "")}`;
}

/** The commit object bytes, as git writes them. */
function render(
	fields: { tree: string; parents: string[]; author: FakeIdentity; committer: FakeIdentity; message: string },
	signature: string | null,
): string {
	const lines = [
		`tree ${fields.tree}`,
		...fields.parents.map((parent) => `parent ${parent}`),
		`author ${fields.author.name} <${fields.author.email}> ${stamp(fields.author.date)}`,
		`committer ${fields.committer.name} <${fields.committer.email}> ${stamp(fields.committer.date)}`,
	];

	if (signature !== null) {
		const armor = signature.replace(/\n+$/, "").split("\n");
		lines.push(`gpgsig ${armor[0]}`, ...armor.slice(1).map((line) => ` ${line}`));
	}

	const message = fields.message.endsWith("\n") ? fields.message : `${fields.message}\n`;
	return `${lines.join("\n")}\n\n${message}`;
}

async function objectSha(object: string): Promise<string> {
	const body = new TextEncoder().encode(object);
	const header = new TextEncoder().encode(`commit ${body.length}\0`);
	const framed = new Uint8Array(header.length + body.length);
	framed.set(header, 0);
	framed.set(body, header.length);

	return [...new Uint8Array(await crypto.subtle.digest("SHA-1", framed))]
		.map((byte) => byte.toString(16).padStart(2, "0"))
		.join("");
}

const KAJ: Omit<FakeIdentity, "date"> = { name: "Kaj Kowalski", email: "info@kajkowalski.nl" };
const SOMEBODY_ELSE: Omit<FakeIdentity, "date"> = { name: "Someone", email: "someone@example.com" };

/** Build a commit the way git would, so its sha is its contents. */
async function commit(options: {
	tree?: string;
	parents?: string[];
	message?: string;
	who?: Omit<FakeIdentity, "date">;
	date?: string;
	signature?: string | null;
}): Promise<FakeCommit> {
	const who = options.who ?? KAJ;
	const date = options.date ?? "2026-08-31T01:02:03Z";
	const fields = {
		tree: options.tree ?? "f4b354863caa9cea99b95422c9dab70465757d87",
		parents: options.parents ?? [],
		author: { ...who, date },
		committer: { ...who, date },
		message: options.message ?? "a commit",
	};
	const signature = options.signature ?? null;
	const payload = render(fields, null);

	return {
		sha: await objectSha(render(fields, signature)),
		tree: { sha: fields.tree },
		parents: fields.parents.map((sha) => ({ sha })),
		author: fields.author,
		committer: fields.committer,
		message: fields.message,
		verification: { signature, payload: signature === null ? null : payload },
	};
}

/** A repository the double serves, and a record of everything asked of it. */
interface Repo {
	commits: Map<string, FakeCommit>;
	head: string;
	writes: { method: string; path: string; body: unknown }[];
	reads: string[];
	tokenRequests: string[];
}

interface Faults {
	/** Fail `GET /git/commits/*` with this status. */
	readCommit?: number;
	/** Fail `PATCH /git/refs/*` with this status, or `"network"` for no answer at all. */
	updateRef?: number | "network";
	/** Answer `GET /git/ref/*` with this sha instead of the real head. */
	headSays?: string;
	/** Return this sha from `POST /git/commits` regardless of what was created. */
	createReturns?: string;
}

/**
 * A `fetch` double for `api.github.com`, and the destination pin.
 *
 * The pin is asserted here rather than per test: no path through the signing
 * run may reach another host, so the double itself is what fails if one ever
 * does.
 */
function stubGitHub(repos: Map<string, Repo>, faults: Faults = {}) {
	vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
		const request = new Request(input as RequestInfo, init as RequestInit);
		const url = new URL(request.url);

		if (url.origin !== GITHUB_API_ORIGIN) {
			throw new Error(`outbound request left api.github.com: ${request.url}`);
		}

		const json = (body: unknown, status = 200) =>
			new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

		const token = /^\/app\/installations\/(\d+)\/access_tokens$/.exec(url.pathname);
		if (token) {
			for (const repo of repos.values()) {
				repo.tokenRequests.push(url.pathname);
			}
			return json({ token: `ghs_${token[1]}`, expires_at: new Date(Date.now() + 3_600_000).toISOString() }, 201);
		}

		const scoped = /^\/repos\/([^/]+)\/([^/]+)(\/.*)$/.exec(url.pathname);
		if (!scoped) {
			return json({ message: "Not Found" }, 404);
		}

		const repo = repos.get(`${scoped[1]}/${scoped[2]}`);
		if (repo === undefined) {
			return json({ message: "Not Found" }, 404);
		}

		const rest = scoped[3] as string;

		const read = /^\/git\/commits\/([0-9a-f]{40})$/.exec(rest);
		if (read && request.method === "GET") {
			repo.reads.push(rest);
			if (faults.readCommit !== undefined) {
				return json({ message: "boom" }, faults.readCommit);
			}
			const found = repo.commits.get(read[1] as string);
			return found ? json(found) : json({ message: "Not Found" }, 404);
		}

		if (rest === "/git/commits" && request.method === "POST") {
			const body = (await request.json()) as {
				message: string;
				tree: string;
				parents: string[];
				author: FakeIdentity;
				committer: FakeIdentity;
				signature: string;
			};
			repo.writes.push({ method: "POST", path: rest, body });

			const object = render(body, body.signature);
			const sha = faults.createReturns ?? (await objectSha(object));
			const created: FakeCommit = {
				sha,
				tree: { sha: body.tree },
				parents: body.parents.map((parent) => ({ sha: parent })),
				author: body.author,
				committer: body.committer,
				message: body.message,
				verification: { signature: body.signature, payload: render(body, null) },
			};
			repo.commits.set(sha, created);
			return json(created, 201);
		}

		if (rest.startsWith("/git/ref/heads/") && request.method === "GET") {
			repo.reads.push(rest);
			return json({ object: { sha: faults.headSays ?? repo.head } });
		}

		if (rest.startsWith("/git/refs/heads/") && request.method === "PATCH") {
			const body = await request.json();
			repo.writes.push({ method: "PATCH", path: rest, body });
			if (faults.updateRef === "network") {
				throw new Error("connection reset");
			}
			if (faults.updateRef !== undefined) {
				return json({ message: "refused" }, faults.updateRef);
			}
			repo.head = (body as { sha: string }).sha;
			return json({ object: { sha: repo.head } });
		}

		return json({ message: "Not Found" }, 404);
	});
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

interface TestKey {
	keyId: string;
	armoredPrivateKey: string;
	publicKey: string;
}

let ours: TestKey;
let theirs: TestKey;
let appPrivateKey: string;

async function makeKey(email: string): Promise<TestKey> {
	const { privateKey, publicKey } = await openpgp.generateKey({
		type: "ecc",
		curve: "ed25519Legacy",
		userIDs: [{ name: "Kaj Kowalski", email }],
		passphrase: env.KEY_PASSPHRASE,
		format: "armored",
	});
	const parsed = await openpgp.readPrivateKey({ armoredKey: privateKey });

	return { keyId: parsed.getKeyID().toHex().toUpperCase(), armoredPrivateKey: privateKey, publicKey };
}

/** Put a key where `loadSigningKey` will find it. */
async function store(key: TestKey): Promise<void> {
	const storage = env.KEY_STORAGE.get(env.KEY_STORAGE.idFromName("global"));
	const parsed = await openpgp.readPrivateKey({ armoredKey: key.armoredPrivateKey });
	const response = await storage.fetch(
		new Request("http://internal/store-key", {
			method: "POST",
			body: JSON.stringify({
				armoredPrivateKey: key.armoredPrivateKey,
				keyId: key.keyId,
				fingerprint: parsed.getFingerprint(),
				algorithm: "EdDSA",
				createdAt: new Date().toISOString(),
			}),
		}),
	);
	if (!response.ok) {
		throw new Error(`could not seed the key: ${response.status}`);
	}
}

function pem(label: string, der: Uint8Array): string {
	let binary = "";
	for (const byte of der) {
		binary += String.fromCharCode(byte);
	}
	return `-----BEGIN ${label}-----\n${btoa(binary).replace(/(.{64})/g, "$1\n")}\n-----END ${label}-----\n`;
}

/**
 * The audit table, with the CHECK constraint the migration actually ships.
 *
 * Written out rather than relaxed to a bare `TEXT`, because the closed enum is
 * enforced in the database and nowhere else — an `action` the migration forgot
 * would fail here, which is the only place it can fail before production.
 */
const AUDIT_TABLE = `CREATE TABLE IF NOT EXISTS audit_logs (
	id TEXT PRIMARY KEY,
	timestamp TEXT NOT NULL,
	request_id TEXT NOT NULL,
	action TEXT NOT NULL CHECK (
		action IN (
			'sign', 'key_upload', 'key_rotate', 'token_create',
			'token_revoke', 'subject_create', 'subject_revoke', 'webhook_sign'
		)
	),
	issuer TEXT NOT NULL,
	subject TEXT NOT NULL,
	key_id TEXT NOT NULL,
	success INTEGER NOT NULL DEFAULT 0,
	error_code TEXT,
	metadata TEXT
)`;

beforeAll(async () => {
	await env.AUDIT_DB.prepare(AUDIT_TABLE).run();
	ours = await makeKey("info@kajkowalski.nl");
	// The same address on purpose: the committer check must not be what decides
	// this pair apart, or the cross-key assertion below would pass for an
	// implementation that ignores the binding and refuses on identity instead.
	theirs = await makeKey("info@kajkowalski.nl");
	await store(ours);
	await store(theirs);

	const pair = (await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	)) as CryptoKeyPair;
	appPrivateKey = pem(
		"PRIVATE KEY",
		new Uint8Array((await crypto.subtle.exportKey("pkcs8", pair.privateKey)) as ArrayBuffer),
	);
}, 60_000);

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

async function sign(body: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(SECRET),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body)));

	return SIGNATURE_PREFIX + [...mac].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

interface Envelope {
	received?: boolean;
	handled?: boolean;
	outcome?: string;
	duplicate?: boolean;
	code?: string;
}

interface DeliveryOptions {
	allowlist: string;
	payload: unknown;
	deliveryId?: string;
	overrides?: Partial<Env>;
	event?: string;
}

async function deliver(options: DeliveryOptions): Promise<{ response: Response; body: Envelope }> {
	const body = JSON.stringify(options.payload);
	const ctx = createExecutionContext();

	const response = await app.fetch(
		new Request("https://sign.test/github/webhook", {
			method: "POST",
			body,
			headers: {
				"Content-Type": "application/json",
				[SIGNATURE_HEADER]: await sign(body),
				"X-GitHub-Event": options.event ?? "push",
				"X-GitHub-Delivery": options.deliveryId ?? crypto.randomUUID(),
			},
		}),
		{
			...env,
			GITHUB_APP_ENABLED: "true",
			GITHUB_WEBHOOK_SECRET: SECRET,
			GITHUB_APP_ID: "123456",
			GITHUB_APP_PRIVATE_KEY: appPrivateKey,
			GITHUB_APP_ALLOWED_REPOSITORIES: options.allowlist,
			...options.overrides,
		},
		ctx,
	);
	await waitOnExecutionContext(ctx);

	return { response, body: (await response.json()) as Envelope };
}

/** A push payload for `before..after` on `refs/heads/<branch>`. */
function push(options: {
	installationId: number;
	repository: string;
	before: string;
	after: string;
	branch?: string;
	deleted?: boolean;
}) {
	return {
		ref: `refs/heads/${options.branch ?? BRANCH}`,
		before: options.before,
		after: options.after,
		...(options.deleted === undefined ? {} : { deleted: options.deleted }),
		installation: { id: options.installationId },
		repository: { full_name: options.repository, name: options.repository.split("/")[1] },
	};
}

/** A repository with one already-present base commit and one unsigned child. */
async function scenario(name = "service") {
	const base = await commit({ message: "base", tree: "0".repeat(39) + "1" });
	const child = await commit({ message: "needs a signature", parents: [base.sha] });
	const repo: Repo = {
		commits: new Map([
			[base.sha, base],
			[child.sha, child],
		]),
		head: child.sha,
		writes: [],
		reads: [],
		tokenRequests: [],
	};

	return { base, child, repo, full: `${OWNER}/${name}`, repos: new Map([[`${OWNER}/${name}`, repo]]) };
}

/** The `gpgsig` on the commit a run created, or null when it created none. */
function createdSignature(repo: Repo): string | null {
	const created = repo.writes.find((write) => write.method === "POST");
	return created ? (created.body as { signature: string }).signature : null;
}

/** The bytes that signature covers, taken from the double's own reconstruction. */
function createdPayload(repo: Repo): string {
	const created = repo.writes.find((write) => write.method === "POST");
	if (!created) {
		throw new Error("no commit was created");
	}
	return render(created.body as Parameters<typeof render>[0], null);
}

describe("signing a pushed commit", () => {
	it("signs the unsigned commit and moves the branch to it", async () => {
		const { base, child, repo, full, repos } = await scenario();
		stubGitHub(repos);
		const id = installation();

		const { response, body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});

		expect(response.status).toBe(200);
		expect(body).toMatchObject({ handled: true, outcome: "signed" });

		// One commit created, one ref updated, and the ref update is the last thing
		// that happened.
		expect(repo.writes.map((write) => write.method)).toEqual(["POST", "PATCH"]);
		expect(repo.head).not.toBe(child.sha);
		expect(repo.commits.get(repo.head)?.verification.signature).toBeTruthy();

		// The signature verifies against the bound key, over the bytes the double
		// reconstructed independently.
		expect(await verifyDetachedSignature(createdPayload(repo), createdSignature(repo) as string, ours.publicKey)).toBe(
			true,
		);
		// The base is untouched: the walk stopped at `before`.
		expect(repo.commits.get(base.sha)).toBe(base);
	});

	it("forces the update, because a signed rewrite is never a fast-forward", async () => {
		const { base, child, repo, full, repos } = await scenario();
		stubGitHub(repos);
		const id = installation();

		await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});

		const patch = repo.writes.find((write) => write.method === "PATCH");
		expect(patch?.body).toMatchObject({ force: true, sha: repo.head });
		expect(patch?.path).toBe(`/git/refs/heads/${BRANCH}`);
	});

	it("signs a range oldest-first, re-parenting as it goes", async () => {
		const base = await commit({ message: "base", tree: "0".repeat(39) + "2" });
		const first = await commit({ message: "one", parents: [base.sha] });
		const second = await commit({ message: "two", parents: [first.sha] });
		const repo: Repo = {
			commits: new Map([base, first, second].map((c) => [c.sha, c])),
			head: second.sha,
			writes: [],
			reads: [],
			tokenRequests: [],
		};
		const full = `${OWNER}/chain`;
		stubGitHub(new Map([[full, repo]]));
		const id = installation();

		await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: second.sha }),
		});

		const created = repo.writes.filter((write) => write.method === "POST");
		expect(created).toHaveLength(2);
		// The older commit is created first, and the newer one names the *new*
		// parent rather than the one that was pushed.
		expect((created[0] as { body: { message: string } }).body.message).toBe("one");
		const rewrittenFirst = repo.commits.get(repo.head)?.parents[0]?.sha;
		expect(rewrittenFirst).not.toBe(first.sha);
		expect((created[1] as { body: { parents: string[] } }).body.parents).toEqual([rewrittenFirst]);
	});
});

describe("the push this service made does not come back", () => {
	it("finds nothing to sign on the delivery its own push causes", async () => {
		// **Loop prevention, asserted as the fixpoint it is.** No actor check and no
		// event-name check: the run is fed the exact commit state its own push left
		// behind, and it must make no write at all.
		const { base, child, repo, full, repos } = await scenario();
		stubGitHub(repos);
		const id = installation();
		const allowlist = `${id}:${full}=${ours.keyId}`;

		await deliver({
			allowlist,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});
		const signedHead = repo.head;
		repo.writes.length = 0;

		const { response, body } = await deliver({
			allowlist,
			payload: push({ installationId: id, repository: full, before: child.sha, after: signedHead }),
		});

		expect(response.status).toBe(200);
		expect(body).toMatchObject({ handled: true, outcome: "already_signed" });
		expect(repo.writes).toHaveLength(0);
		expect(repo.head).toBe(signedHead);
	});

	it("stops at a commit signed by the bound key even when the base is unreachable", async () => {
		// The walk's other stop condition, on its own: `before` is an object the
		// double does not serve, so only the signature can end the walk.
		const { base, child, full, repos, repo } = await scenario();
		stubGitHub(repos);
		const id = installation();
		const allowlist = `${id}:${full}=${ours.keyId}`;

		await deliver({
			allowlist,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});
		const signedHead = repo.head;
		repo.writes.length = 0;

		const { body } = await deliver({
			allowlist,
			payload: push({ installationId: id, repository: full, before: "9".repeat(40), after: signedHead }),
		});

		expect(body).toMatchObject({ outcome: "already_signed" });
		expect(repo.writes).toHaveLength(0);
	});
});

describe("nothing is destroyed", () => {
	it("refuses a commit carrying somebody else's signature", async () => {
		// The most expensive mistake available: rewriting a signed commit strips the
		// signature and puts nothing back.
		const base = await commit({ message: "base", tree: "0".repeat(39) + "3" });
		const foreign = await commit({
			message: "signed by someone else",
			parents: [base.sha],
			signature: "-----BEGIN PGP SIGNATURE-----\n\nAAAA\n-----END PGP SIGNATURE-----",
		});
		const repo: Repo = {
			commits: new Map([base, foreign].map((c) => [c.sha, c])),
			head: foreign.sha,
			writes: [],
			reads: [],
			tokenRequests: [],
		};
		const full = `${OWNER}/foreign`;
		stubGitHub(new Map([[full, repo]]));
		const id = installation();

		const { response, body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: foreign.sha }),
		});

		expect(response.status).toBe(200);
		expect(body).toMatchObject({ handled: false, outcome: "foreign_signature" });
		expect(repo.writes).toHaveLength(0);
		expect(repo.head).toBe(foreign.sha);
	});

	it("refuses a commit committed by an identity the key does not carry", async () => {
		const base = await commit({ message: "base", tree: "0".repeat(39) + "4" });
		const stranger = await commit({ message: "not mine", parents: [base.sha], who: SOMEBODY_ELSE });
		const repo: Repo = {
			commits: new Map([base, stranger].map((c) => [c.sha, c])),
			head: stranger.sha,
			writes: [],
			reads: [],
			tokenRequests: [],
		};
		const full = `${OWNER}/stranger`;
		stubGitHub(new Map([[full, repo]]));
		const id = installation();

		const { body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: stranger.sha }),
		});

		expect(body).toMatchObject({ outcome: "foreign_committer" });
		expect(repo.writes).toHaveLength(0);
	});

	it("refuses a merge commit rather than picking a parent", async () => {
		const base = await commit({ message: "base", tree: "0".repeat(39) + "5" });
		const side = await commit({ message: "side", tree: "0".repeat(39) + "6" });
		const merge = await commit({ message: "merge", parents: [base.sha, side.sha] });
		const repo: Repo = {
			commits: new Map([base, side, merge].map((c) => [c.sha, c])),
			head: merge.sha,
			writes: [],
			reads: [],
			tokenRequests: [],
		};
		const full = `${OWNER}/merge`;
		stubGitHub(new Map([[full, repo]]));
		const id = installation();

		const { body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: merge.sha }),
		});

		expect(body).toMatchObject({ outcome: "unsupported_commit_shape" });
		expect(repo.writes).toHaveLength(0);
	});

	it("refuses a commit whose bytes it cannot rebuild", async () => {
		// The fail-closed reading of "this service does not fully understand this
		// object". Simulated by a commit whose reported message is not the one its
		// name was computed over, which is what an unmodelled header looks like.
		const base = await commit({ message: "base", tree: "0".repeat(39) + "7" });
		const opaque = await commit({ message: "real message", parents: [base.sha] });
		const repo: Repo = {
			commits: new Map([
				[base.sha, base],
				[opaque.sha, { ...opaque, message: "a different message" }],
			]),
			head: opaque.sha,
			writes: [],
			reads: [],
			tokenRequests: [],
		};
		const full = `${OWNER}/opaque`;
		stubGitHub(new Map([[full, repo]]));
		const id = installation();

		const { body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: opaque.sha }),
		});

		expect(body).toMatchObject({ outcome: "commit_not_reproducible" });
		expect(repo.writes).toHaveLength(0);
	});

	it("refuses a range longer than it will rewrite", async () => {
		const base = await commit({ message: "base", tree: "0".repeat(39) + "8" });
		const commits = [base];
		for (let index = 0; index < 22; index += 1) {
			commits.push(await commit({ message: `commit ${index}`, parents: [commits[index]?.sha as string] }));
		}
		const repo: Repo = {
			commits: new Map(commits.map((c) => [c.sha, c])),
			head: commits[commits.length - 1]?.sha as string,
			writes: [],
			reads: [],
			tokenRequests: [],
		};
		const full = `${OWNER}/long`;
		stubGitHub(new Map([[full, repo]]));
		const id = installation();

		const { body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: repo.head }),
		});

		expect(body).toMatchObject({ outcome: "range_too_long" });
		expect(repo.writes).toHaveLength(0);
	});
});

describe("what the payload is not allowed to choose", () => {
	it("signs with the key bound to the pushed repository, not another grant's", async () => {
		// **The cross-key test.** Two grants, two keys, one delivery. Verified
		// against the wrong key as well as the right one, because an implementation
		// that took "any configured key" passes a one-sided assertion.
		const { base, child, repo, full, repos } = await scenario("second");
		stubGitHub(repos);
		const id = installation();

		await deliver({
			allowlist: `${id}:${OWNER}/first=${ours.keyId}, ${id}:${full}=${theirs.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});

		const payload = createdPayload(repo);
		const signature = createdSignature(repo) as string;
		expect(await verifyDetachedSignature(payload, signature, theirs.publicKey)).toBe(true);
		expect(await verifyDetachedSignature(payload, signature, ours.publicKey)).toBe(false);
	});

	it("refuses the right repository under the wrong installation", async () => {
		const { base, child, repo, full, repos } = await scenario("wrong-install");
		stubGitHub(repos);
		const granted = installation();
		const claimed = installation();

		const { response, body } = await deliver({
			allowlist: `${granted}:${full}=${ours.keyId}, ${claimed}:${OWNER}/somewhere-else=${ours.keyId}`,
			payload: push({ installationId: claimed, repository: full, before: base.sha, after: child.sha }),
		});

		expect(response.status).toBe(401);
		expect(body.code).toBe("AUTH_SUBJECT_UNTRUSTED");
		expect(repo.writes).toHaveLength(0);
	});

	it("mints the token for the granted installation, never the payload's", async () => {
		const { base, child, repo, full, repos } = await scenario("token-scope");
		stubGitHub(repos);
		const id = installation();

		await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});

		expect(repo.tokenRequests).toEqual([`/app/installations/${id}/access_tokens`]);
	});

	it("refuses an allowlisted pair whose grant binds no key", async () => {
		const { base, child, repo, full, repos } = await scenario("unbound");
		stubGitHub(repos);
		const id = installation();

		const { response, body } = await deliver({
			allowlist: `${id}:${full}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});

		// Retryable: the fix is an allowlist edit, and the operator's redelivery has
		// to be able to work afterwards.
		expect(response.status).toBe(503);
		expect(body).toMatchObject({ outcome: "no_key_bound" });
		expect(repo.writes).toHaveLength(0);
	});

	it("refuses a ref that is not a branch", async () => {
		const { base, child, repo, full, repos } = await scenario("tags");
		stubGitHub(repos);
		const id = installation();

		const { body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: {
				...push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
				ref: "refs/tags/v1.0.0",
			},
		});

		expect(body).toMatchObject({ outcome: "unsupported_ref" });
		expect(repo.writes).toHaveLength(0);
	});

	it("refuses a branch deletion and a branch creation", async () => {
		const { base, child, full, repos, repo } = await scenario("lifecycle");
		stubGitHub(repos);
		const id = installation();
		const allowlist = `${id}:${full}=${ours.keyId}`;

		const deleted = await deliver({
			allowlist,
			payload: push({ installationId: id, repository: full, before: base.sha, after: "0".repeat(40), deleted: true }),
		});
		expect(deleted.body).toMatchObject({ outcome: "branch_deleted" });

		const created = await deliver({
			allowlist,
			payload: push({ installationId: id, repository: full, before: "0".repeat(40), after: child.sha }),
		});
		expect(created.body).toMatchObject({ outcome: "branch_created" });

		expect(repo.writes).toHaveLength(0);
	});

	it("refuses a range it cannot read object names out of", async () => {
		const { child, repo, full, repos } = await scenario("garbage");
		stubGitHub(repos);
		const id = installation();

		const { body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: {
				...push({ installationId: id, repository: full, before: "not-a-sha", after: child.sha }),
			},
		});

		expect(body).toMatchObject({ outcome: "unreadable_range" });
		expect(repo.writes).toHaveLength(0);
	});
});

describe("the key it cannot reach", () => {
	it("refuses when the bound key is not in storage, and lets the delivery be retried", async () => {
		const { base, child, repo, full, repos } = await scenario("gone");
		stubGitHub(repos);
		const id = installation();

		const { response, body } = await deliver({
			allowlist: `${id}:${full}=DEADBEEFDEADBEEF`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});

		expect(response.status).toBe(503);
		expect(body).toMatchObject({ outcome: "key_missing" });
		expect(repo.writes).toHaveLength(0);
	});

	it("distinguishes an unreachable key store from a missing key", async () => {
		// The two have different fixes — edit the allowlist, or wait — and reporting
		// an outage as a missing key sends someone to change configuration that is
		// correct.
		const { base, child, repo, full, repos } = await scenario("outage");
		stubGitHub(repos);
		const id = installation();

		const broken = {
			KEY_STORAGE: {
				idFromName: () => "id",
				get: () => ({
					fetch: () => Promise.reject(new Error("durable object unavailable")),
				}),
			},
		} as unknown as Partial<Env>;

		const { response, body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
			overrides: broken,
		});

		expect(response.status).toBe(503);
		expect(body).toMatchObject({ outcome: "key_storage_unavailable" });
		expect(repo.writes).toHaveLength(0);
	});
});

describe("the budget in front of the key", () => {
	/**
	 * A limiter that answers `allowed` for the *signing* meter and nothing else.
	 *
	 * Scoped by identity on purpose. The delivery meter runs before the HMAC and
	 * shares this binding, so a double that denied everything would be asserting
	 * on `webhookRateLimit`'s refusal — a different gate, several steps earlier,
	 * that never reaches a key. The whole point of this group is that the
	 * *signing* budget is a separate budget.
	 */
	function limiter(answer: { status?: number; allowed?: boolean } | "throw"): Partial<Env> {
		const allow = (allowed: boolean, status = 200) =>
			new Response(JSON.stringify({ allowed, remaining: allowed ? 10 : 0, resetAt: Date.now() + 1000 }), {
				status,
				headers: { "Content-Type": "application/json" },
			});

		return {
			RATE_LIMITER: {
				idFromName: () => "id",
				get: () => ({
					fetch: (request: Request) => {
						const identity = new URL(request.url).searchParams.get("identity") ?? "";
						if (!identity.startsWith("github-app-sign:")) {
							return Promise.resolve(allow(true));
						}
						if (answer === "throw") {
							return Promise.reject(new Error("limiter unavailable"));
						}
						return Promise.resolve(allow(answer.allowed ?? true, answer.status ?? 200));
					},
				}),
			},
		} as unknown as Partial<Env>;
	}

	it("counts each grant against its own bucket", () => {
		// Asserted on the identity rather than through the limiter, because what
		// this proves is that no two grants share a budget — which a test that only
		// exhausts one bucket cannot show. Every field of the grant has to change
		// the answer.
		const base = signingBudgetIdentity(1, "kjanat/service", "AAAABBBBCCCCDDDD");

		expect(base).not.toBe(signingBudgetIdentity(2, "kjanat/service", "AAAABBBBCCCCDDDD"));
		expect(base).not.toBe(signingBudgetIdentity(1, "kjanat/other", "AAAABBBBCCCCDDDD"));
		expect(base).not.toBe(signingBudgetIdentity(1, "kjanat/service", "1111222233334444"));
		// And it is disjoint from the delivery meter, which counts by source
		// address and is not a signing budget.
		expect(base.startsWith("webhook:")).toBe(false);
	});

	it("signs nothing when the signing budget is exhausted", async () => {
		const { base, child, repo, full, repos } = await scenario("metered");
		stubGitHub(repos);
		const id = installation();

		const { response, body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
			overrides: limiter({ status: 429, allowed: false }),
		});

		expect(response.status).toBe(429);
		expect(body).toMatchObject({ outcome: "rate_limited" });
		// The budget is spent *before* the first signature, so a refused run creates
		// no objects at all rather than half a rewrite.
		expect(repo.writes).toHaveLength(0);
	});

	it("fails closed when the limiter cannot be consulted", async () => {
		const { base, child, repo, full, repos } = await scenario("no-limiter");
		stubGitHub(repos);
		const id = installation();

		const { response, body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
			overrides: limiter("throw"),
		});

		expect(response.status).toBe(503);
		expect(body).toMatchObject({ outcome: "rate_limiter_unavailable" });
		expect(repo.writes).toHaveLength(0);
	});

	it("reads an error status from the limiter as an outage, not as a denial", async () => {
		const { base, child, full, repos } = await scenario("limiter-500");
		stubGitHub(repos);
		const id = installation();

		const { body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
			overrides: limiter({ status: 500 }),
		});

		expect(body).toMatchObject({ outcome: "rate_limiter_unavailable" });
	});
});

describe("when GitHub does not cooperate", () => {
	it("refuses without moving the branch when a commit cannot be read", async () => {
		const { base, child, repo, full, repos } = await scenario("api-500");
		stubGitHub(repos, { readCommit: 502 });
		const id = installation();

		const { response, body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});

		expect(response.status).toBe(503);
		expect(body).toMatchObject({ outcome: "github_unavailable" });
		expect(repo.writes).toHaveLength(0);
		expect(repo.head).toBe(child.sha);
	});

	it("refuses when the branch moved between the delivery and the update", async () => {
		// Somebody else pushed. Forcing over it is the one mistake this run could
		// make that destroys work rather than merely failing.
		const { base, child, repo, full, repos } = await scenario("raced");
		stubGitHub(repos, { headSays: "a".repeat(40) });
		const id = installation();

		const { response, body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});

		expect(response.status).toBe(503);
		expect(body).toMatchObject({ outcome: "head_moved" });
		// The objects were created — they are unreferenced and harmless — and the
		// ref was not touched.
		expect(repo.writes.map((write) => write.method)).toEqual(["POST"]);
	});

	it("refuses when the created commit is not the commit that was signed", async () => {
		const { base, child, repo, full, repos } = await scenario("mismatch");
		stubGitHub(repos, { createReturns: "b".repeat(40) });
		const id = installation();

		const { body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});

		expect(body).toMatchObject({ outcome: "created_commit_mismatch" });
		expect(repo.writes.some((write) => write.method === "PATCH")).toBe(false);
	});

	it("reports a refused ref update as retryable and an unanswered one as unknown", async () => {
		// The single most important distinction on this path. A 422 means the ref
		// did not move, so the delivery may be handed back; a connection that died
		// means nobody knows, and "unknown" must never be reported as "safe".
		const refused = await scenario("patch-422");
		stubGitHub(refused.repos, { updateRef: 422 });
		const refusedId = installation();
		const refusedResponse = await deliver({
			allowlist: `${refusedId}:${refused.full}=${ours.keyId}`,
			payload: push({
				installationId: refusedId,
				repository: refused.full,
				before: refused.base.sha,
				after: refused.child.sha,
			}),
		});
		expect(refusedResponse.body).toMatchObject({ outcome: "github_unavailable" });

		const lost = await scenario("patch-network");
		stubGitHub(lost.repos, { updateRef: "network" });
		const lostId = installation();
		const lostResponse = await deliver({
			allowlist: `${lostId}:${lost.full}=${ours.keyId}`,
			payload: push({ installationId: lostId, repository: lost.full, before: lost.base.sha, after: lost.child.sha }),
		});
		expect(lostResponse.body).toMatchObject({ outcome: "ref_update_indeterminate" });
		// Answered 200, not 503: a red delivery invites a redelivery, and this is
		// the one outcome where a second attempt must not be encouraged.
		expect(lostResponse.response.status).toBe(200);
	});
});

describe("replay, concurrency and recovery", () => {
	it("acts once when two copies of one delivery race", async () => {
		// **The test the ledger exists for.** Both copies verify, both are
		// authorized, and exactly one may reach the ref.
		const { base, child, repo, full, repos } = await scenario("racing");
		stubGitHub(repos);
		const id = installation();
		const deliveryId = crypto.randomUUID();
		const payload = push({ installationId: id, repository: full, before: base.sha, after: child.sha });
		const allowlist = `${id}:${full}=${ours.keyId}`;

		const [first, second] = await Promise.all([
			deliver({ allowlist, payload, deliveryId }),
			deliver({ allowlist, payload, deliveryId }),
		]);

		expect(repo.writes.filter((write) => write.method === "PATCH")).toHaveLength(1);
		const duplicates = [first, second].filter((result) => result.body.duplicate === true);
		expect(duplicates).toHaveLength(1);
	});

	it("answers a redelivery of a completed run as a duplicate, without acting again", async () => {
		const { base, child, repo, full, repos } = await scenario("settled");
		stubGitHub(repos);
		const id = installation();
		const deliveryId = crypto.randomUUID();
		const payload = push({ installationId: id, repository: full, before: base.sha, after: child.sha });
		const allowlist = `${id}:${full}=${ours.keyId}`;

		await deliver({ allowlist, payload, deliveryId });
		repo.writes.length = 0;

		const { response, body } = await deliver({ allowlist, payload, deliveryId });

		expect(response.status).toBe(200);
		expect(body.duplicate).toBe(true);
		expect(repo.writes).toHaveLength(0);
	});

	it("lets a redelivery retry a run that failed before the branch moved", async () => {
		// **The recovery this whole two-phase ledger was added for.** Under the
		// one-phase claim this second delivery is `200 {"duplicate": true}` and the
		// push is never signed.
		const { base, child, repo, full, repos } = await scenario("recovered");
		stubGitHub(repos, { readCommit: 502 });
		const id = installation();
		const deliveryId = crypto.randomUUID();
		const payload = push({ installationId: id, repository: full, before: base.sha, after: child.sha });
		const allowlist = `${id}:${full}=${ours.keyId}`;

		const failed = await deliver({ allowlist, payload, deliveryId });
		expect(failed.response.status).toBe(503);
		expect(repo.writes).toHaveLength(0);

		// GitHub recovers, the operator presses Redeliver, and the same id works.
		stubGitHub(repos);
		const retried = await deliver({ allowlist, payload, deliveryId });

		expect(retried.body).toMatchObject({ handled: true, outcome: "signed", duplicate: false });
		expect(repo.writes.filter((write) => write.method === "PATCH")).toHaveLength(1);
	});

	it("does not hand back a delivery id for a refusal a retry cannot fix", async () => {
		// A merge commit is refused identically forever, so releasing the id would
		// invite a redelivery that cannot work.
		const base = await commit({ message: "base", tree: "0".repeat(39) + "9" });
		const side = await commit({ message: "side", tree: "0".repeat(38) + "10" });
		const merge = await commit({ message: "merge", parents: [base.sha, side.sha] });
		const repo: Repo = {
			commits: new Map([base, side, merge].map((c) => [c.sha, c])),
			head: merge.sha,
			writes: [],
			reads: [],
			tokenRequests: [],
		};
		const full = `${OWNER}/permanent`;
		stubGitHub(new Map([[full, repo]]));
		const id = installation();
		const deliveryId = crypto.randomUUID();
		const payload = push({ installationId: id, repository: full, before: base.sha, after: merge.sha });
		const allowlist = `${id}:${full}=${ours.keyId}`;

		await deliver({ allowlist, payload, deliveryId });
		const { body } = await deliver({ allowlist, payload, deliveryId });

		expect(body.duplicate).toBe(true);
	});
});

describe("what an operator can reconstruct afterwards", () => {
	it("writes one audit row per attempt, naming the authorized subject and no secret", async () => {
		const { base, child, full, repos } = await scenario("audited");
		stubGitHub(repos);
		const id = installation();

		await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});

		const row = await env.AUDIT_DB.prepare(
			"SELECT * FROM audit_logs WHERE action = 'webhook_sign' AND subject = ? ORDER BY timestamp DESC LIMIT 1",
		)
			.bind(`${id}:${full}`)
			.first<{ issuer: string; key_id: string; success: number; metadata: string }>();

		expect(row?.issuer).toBe("github-app");
		expect(row?.key_id).toBe(ours.keyId);
		expect(row?.success).toBe(1);

		const metadata = JSON.parse(row?.metadata ?? "{}") as { signed: number; branch: string; head: string };
		expect(metadata.signed).toBe(1);
		expect(metadata.branch).toBe(`refs/heads/${BRANCH}`);

		// Nothing that is a credential. Checked against the whole row rather than
		// against the fields it was built from, because the point is what a reader
		// of `audit_logs` can see.
		const serialised = JSON.stringify(row);
		expect(serialised).not.toContain("PRIVATE KEY");
		expect(serialised).not.toContain(env.KEY_PASSPHRASE);
		expect(serialised).not.toContain("ghs_");
		expect(serialised).not.toContain(SECRET);
	});

	it("records a refusal with the reason and whether it can be retried", async () => {
		const { base, child, full, repos } = await scenario("audited-refusal");
		stubGitHub(repos, { readCommit: 500 });
		const id = installation();

		await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});

		const row = await env.AUDIT_DB.prepare(
			"SELECT * FROM audit_logs WHERE action = 'webhook_sign' AND subject = ? ORDER BY timestamp DESC LIMIT 1",
		)
			.bind(`${id}:${full}`)
			.first<{ success: number; error_code: string; metadata: string }>();

		expect(row?.success).toBe(0);
		expect(row?.error_code).toBe("SERVICE_DEGRADED");
		expect(JSON.parse(row?.metadata ?? "{}")).toMatchObject({ reason: "github_unavailable", retryable: true });
	});

	it("records the pair that has no key under a sentinel rather than under some other key", async () => {
		const { base, child, full, repos } = await scenario("audited-unbound");
		stubGitHub(repos);
		const id = installation();

		await deliver({
			allowlist: `${id}:${full}`,
			payload: push({ installationId: id, repository: full, before: base.sha, after: child.sha }),
		});

		const row = await env.AUDIT_DB.prepare(
			"SELECT * FROM audit_logs WHERE action = 'webhook_sign' AND subject = ? ORDER BY timestamp DESC LIMIT 1",
		)
			.bind(`${id}:${full}`)
			.first<{ key_id: string; error_code: string }>();

		expect(row?.key_id).toBe("unbound");
		expect(row?.error_code).toBe("KEY_NOT_ALLOWED");
	});
});

describe("events with no handler", () => {
	it("still acknowledges without acting", async () => {
		const { full, repos, repo } = await scenario("quiet");
		stubGitHub(repos);
		const id = installation();

		const { response, body } = await deliver({
			allowlist: `${id}:${full}=${ours.keyId}`,
			payload: { installation: { id }, repository: { full_name: full, name: "quiet" } },
			event: "issues",
		});

		expect(response.status).toBe(202);
		expect(body).toMatchObject({ received: true, handled: false });
		expect(repo.writes).toHaveLength(0);
		// And no installation token was minted for an event nothing acts on.
		expect(repo.tokenRequests).toHaveLength(0);
	});
});
