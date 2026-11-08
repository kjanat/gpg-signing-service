import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import * as openpgp from "openpgp";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import app from "#gpg-signing-service";
import { BINDING_ISSUER, Signer } from "#signer";
import type { Env } from "#types";
import { createIdentity } from "#types";
import { logAuditEvent } from "#utils/audit";
import { fetchKeyStorage, fetchRateLimiter } from "#utils/durable-objects";
import { clearKeyCache } from "#utils/signing";

vi.mock("#utils/audit", async (importOriginal) => {
	const actual = await importOriginal<typeof import("#utils/audit")>();
	return { ...actual, logAuditEvent: vi.fn(async () => undefined) };
});

function signer(overrides: Partial<Env> = {}): Signer {
	return new Signer(createExecutionContext(), { ...env, ...overrides });
}

describe("Signer entrypoint", () => {
	let publicKey: openpgp.PublicKey;

	beforeAll(async () => {
		const { privateKey } = await openpgp.generateKey({
			type: "ecc",
			curve: "ed25519Legacy",
			userIDs: [{ name: "Release Bot", email: "release@example.com" }],
			passphrase: env.KEY_PASSPHRASE,
			format: "armored",
		});
		publicKey = (await openpgp.readPrivateKey({ armoredKey: privateKey })).toPublic();
		const ctx = createExecutionContext();
		const response = await app.fetch(
			new Request("http://localhost/admin/keys", {
				method: "POST",
				headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}`, "Content-Type": "application/json" },
				body: JSON.stringify({ armoredPrivateKey: privateKey, keyId: env.KEY_ID }),
			}),
			env,
			ctx,
		);
		await waitOnExecutionContext(ctx);
		expect(response.ok).toBe(true);
	});

	beforeEach(() => vi.mocked(logAuditEvent).mockClear());

	it("publishes the default key and its primary user ID", async () => {
		const identity = await signer().identity();
		expect(identity.userId).toBe("Release Bot <release@example.com>");
		expect((await openpgp.readKey({ armoredKey: identity.publicKey })).getFingerprint()).toBe(
			publicKey.getFingerprint(),
		);
	});

	it("signs the exact bytes and audits the caller", async () => {
		const data = "object 0000000000000000000000000000000000000000\ntype commit\ntag v1.0.0\n\nRelease 1.0.0\n";
		const signature = await signer().sign(data, "beepboop:octo/widget");
		const verified = await openpgp.verify({
			message: await openpgp.createMessage({ binary: new TextEncoder().encode(data) }),
			signature: await openpgp.readSignature({ armoredSignature: signature }),
			verificationKeys: publicKey,
		});
		await expect(verified.signatures[0]?.verified).resolves.toBe(true);
		expect(logAuditEvent).toHaveBeenCalledWith(
			env.AUDIT_DB,
			expect.objectContaining({
				action: "sign",
				issuer: BINDING_ISSUER,
				subject: "beepboop:octo/widget",
				keyId: env.KEY_ID,
				success: true,
			}),
		);
	});

	it("audits a failed signature and rethrows", async () => {
		clearKeyCache();
		await expect(signer({ KEY_PASSPHRASE: "wrong passphrase" }).sign("data", "beepboop:octo/widget")).rejects.toThrow();
		expect(logAuditEvent).toHaveBeenCalledWith(
			env.AUDIT_DB,
			expect.objectContaining({ success: false, errorCode: "SIGN_ERROR", subject: "beepboop:octo/widget" }),
		);
	});

	it("refuses a caller over its rate limit", async () => {
		let response = await fetchRateLimiter(env, createIdentity(BINDING_ISSUER, "beepboop:busy"));
		while (response.ok) response = await fetchRateLimiter(env, createIdentity(BINDING_ISSUER, "beepboop:busy"));
		await expect(signer().sign("data", "beepboop:busy")).rejects.toThrow(
			"Signing refused by the rate limiter: HTTP 429",
		);
		expect(logAuditEvent).not.toHaveBeenCalled();
	});

	it("refuses a missing key", async () => {
		await expect(signer({ KEY_ID: "0000000000000001" }).identity()).rejects.toThrow("Key 0000000000000001 not found");
	});

	it("refuses an X.509 key", async () => {
		const pem = (label: string) => `-----BEGIN ${label}-----\n${"A".repeat(120)}\n-----END ${label}-----\n`;
		const stored = await fetchKeyStorage(env, "/store-key", {
			method: "POST",
			body: JSON.stringify({
				type: "x509",
				keyId: "0000000000000002",
				privateKeyPem: pem("PRIVATE KEY"),
				certificatePem: pem("CERTIFICATE"),
				fingerprint: "A".repeat(40),
				createdAt: new Date().toISOString(),
				algorithm: "ECDSA P-256",
			}),
		});
		expect(stored.ok).toBe(true);
		await expect(signer({ KEY_ID: "0000000000000002" }).sign("data", "beepboop:octo/widget")).rejects.toThrow(
			"Key 0000000000000002 is not a PGP key",
		);
	});

	it("refuses a key without a user ID", async () => {
		const original = openpgp.PrivateKey.prototype.getPrimaryUser;
		const primary = vi.spyOn(openpgp.PrivateKey.prototype, "getPrimaryUser").mockImplementationOnce(async function (
			this: openpgp.PrivateKey,
			...args
		) {
			const result = await original.apply(this, args);
			Object.defineProperty(result.user, "userID", { value: null });
			return result;
		});
		await expect(signer().identity()).rejects.toThrow("Signing key has no user ID");
		primary.mockRestore();
	});
});
