/**
 * The check on the service's own signature, and why it is not redundant.
 *
 * `signAndCreate` verifies every signature it produces against the public half
 * of the key that produced it, before the commit object is created and long
 * before any ref moves. Reading the code, that looks like an assertion about
 * openpgp rather than a control — and it is the assertion the loop prevention
 * rests on. A run only rewrites commits carrying no signature that verifies
 * under the bound key, so if a signature this service made did *not* verify
 * under that key, the push it produced would arrive back, be rewritten, and
 * arrive again: an unbounded rewrite loop on somebody's branch.
 *
 * Nothing in the ordinary suite can reach that branch, because openpgp signs
 * correctly. So this file is the one place `signCommitData` is replaced — with
 * a signature made by a *different* key, which is exactly what a
 * mixed-up-key bug would produce — and everything else stays real, including
 * the verification under test.
 */

import { env } from "cloudflare:workers";
import * as openpgp from "openpgp";
import { beforeAll, describe, expect, it, vi } from "vitest";
import type { Env, WebhookAuthorization } from "#types";
import { commitPayload } from "#utils/git-commit";
import { signPushedCommits } from "#utils/push-signing";

const { signCommitData: realSignCommitData } = await vi.importActual<typeof import("#utils/signing")>("#utils/signing");

vi.mock("#utils/signing", async (importOriginal) => {
	const actual = await importOriginal<typeof import("#utils/signing")>();
	return { ...actual, signCommitData: vi.fn() };
});

const { signCommitData } = await import("#utils/signing");

const OWNER_REPO = "kjanat/selfcheck";
const INSTALLATION = 900_001;
const DATE = "2026-08-31T01:02:03Z";
const WHO = { name: "Kaj Kowalski", email: "info@kajkowalski.nl", date: DATE };
const TREE = "f4b354863caa9cea99b95422c9dab70465757d87";
const PARENT = "e".repeat(40);

interface Seeded {
	keyId: string;
	armoredPrivateKey: string;
}

let bound: Seeded;
let impostor: Seeded;
let head: string;
/** A deployment whose App credentials work, so the only failure is the one under test. */
let usable: Env;
let contents: { tree: string; parents: string[]; author: typeof WHO; committer: typeof WHO; message: string };

async function seed(): Promise<Seeded> {
	const { privateKey } = await openpgp.generateKey({
		type: "ecc",
		curve: "ed25519Legacy",
		userIDs: [{ name: "Kaj Kowalski", email: "info@kajkowalski.nl" }],
		passphrase: env.KEY_PASSPHRASE,
		format: "armored",
	});
	const parsed = await openpgp.readPrivateKey({ armoredKey: privateKey });
	const keyId = parsed.getKeyID().toHex().toUpperCase();

	const storage = env.KEY_STORAGE.get(env.KEY_STORAGE.idFromName("global"));
	const response = await storage.fetch(
		new Request("http://internal/store-key", {
			method: "POST",
			body: JSON.stringify({
				armoredPrivateKey: privateKey,
				keyId,
				fingerprint: parsed.getFingerprint(),
				algorithm: "EdDSA",
				createdAt: new Date().toISOString(),
			}),
		}),
	);
	if (!response.ok) {
		throw new Error(`could not seed the key: ${response.status}`);
	}

	return { keyId, armoredPrivateKey: privateKey };
}

/** The object name for `object`, computed here rather than imported. */
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

/** A PKCS#8 PEM for an RSA key, so the App JWT can actually be minted. */
async function appPrivateKey(): Promise<string> {
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

beforeAll(async () => {
	usable = { ...env, GITHUB_APP_ID: "123456", GITHUB_APP_PRIVATE_KEY: await appPrivateKey() } as unknown as Env;
	bound = await seed();
	impostor = await seed();

	contents = { tree: TREE, parents: [PARENT], author: WHO, committer: WHO, message: "needs a signature" };
	head = await objectSha(commitPayload(contents, "newline"));

	vi.spyOn(globalThis, "fetch").mockImplementation((input, init) => {
		const request = new Request(input as RequestInfo, init as RequestInit);
		const url = new URL(request.url);
		const json = (body: unknown, status = 200) =>
			new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

		if (url.pathname.endsWith("/access_tokens")) {
			return Promise.resolve(json({ token: "ghs_x", expires_at: new Date(Date.now() + 3_600_000).toISOString() }, 201));
		}

		if (url.pathname.endsWith(`/git/commits/${head}`)) {
			return Promise.resolve(
				json({
					sha: head,
					tree: { sha: TREE },
					parents: [{ sha: PARENT }],
					author: WHO,
					committer: WHO,
					message: contents.message,
				}),
			);
		}

		// Anything else — and `POST /git/commits` in particular — must not be
		// reached. Reaching it is the failure this file is about.
		return Promise.reject(new Error(`unexpected request: ${request.method} ${url.pathname}`));
	});
}, 60_000);

describe("a signature this service made that does not verify under its own key", () => {
	function authorization(): WebhookAuthorization {
		return { scope: "repository", installationId: INSTALLATION, repository: OWNER_REPO, keyId: bound.keyId };
	}

	function delivery() {
		return {
			ref: "refs/heads/master",
			before: PARENT,
			after: head,
			installation: { id: INSTALLATION },
			repository: { full_name: OWNER_REPO },
		};
	}

	it("is refused before the commit is created, let alone before the branch moves", async () => {
		// The mixed-up-key bug, made concrete: a real signature over the right bytes
		// by the wrong key. It is a *valid* OpenPGP signature, so nothing short of
		// verifying it against the bound key's public half notices.
		vi.mocked(signCommitData).mockImplementation(async (data: string) => {
			const parsed = await openpgp.readPrivateKey({ armoredKey: impostor.armoredPrivateKey });
			return realSignCommitData(
				data,
				{
					armoredPrivateKey: impostor.armoredPrivateKey,
					keyId: impostor.keyId,
					fingerprint: parsed.getFingerprint(),
					createdAt: new Date().toISOString(),
					algorithm: "EdDSA",
				} as Parameters<typeof realSignCommitData>[1],
				env.KEY_PASSPHRASE,
			);
		});

		const outcome = await signPushedCommits(usable, authorization(), delivery());

		// Not `created_commit_mismatch`, and the difference matters: this is caught
		// *before* GitHub is asked to create anything, which is why the fetch double
		// above rejects `POST /git/commits` rather than answering it.
		expect(outcome).toMatchObject({ acted: false, reason: "signature_unverifiable" });
	});

	it("accepts the same run once the signature is made by the bound key", async () => {
		// The control. Without it the test above passes for a run that refuses
		// everything, which is not the property being asserted.
		vi.mocked(signCommitData).mockImplementation(realSignCommitData);

		const outcome = await signPushedCommits(usable, authorization(), delivery());

		expect(outcome).toMatchObject({ acted: false, reason: "github_unavailable" });
	});
});
