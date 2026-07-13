import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { env } from "cloudflare:workers";
import * as jose from "jose";
import {
	createSelfSignedCertificate,
	exportEncryptedPkcs8Pem,
	parsePkcs7SignedDataPem,
	verifyPkcs7SignedData,
} from "micro509";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import app from "#gpg-signing-service";
import type { StoredX509Key } from "#schemas/keys";
import { StoredX509KeySchema } from "#schemas/keys";
import { parseAndValidateX509Key, signCommitDataX509 } from "#utils/x509";

// Mock fetch for JWKS
const { x509FetchMock } = vi.hoisted(() => ({ x509FetchMock: vi.fn() }));

vi.mock("#utils/fetch", () => ({ fetchWithTimeout: x509FetchMock }));

// Mock audit logging to avoid D1 dependency in tests
vi.mock("#utils/audit", async (importOriginal) => {
	const actual = await importOriginal<typeof import("#utils/audit")>();
	return { ...actual, logAuditEvent: vi.fn(async () => undefined) };
});

const parseJson = async <T>(response: Response): Promise<T> => (await response.json()) as T;

interface X509Fixture {
	certificatePem: string;
	encryptedKeyPem: string;
}

async function generateX509Fixture(commonName: string): Promise<X509Fixture> {
	const { certificate, keyPair } = await createSelfSignedCertificate({
		subject: { commonName },
		algorithm: { kind: "ecdsa", curve: "P-256" },
	});
	const encryptedKeyPem = await exportEncryptedPkcs8Pem(keyPair.privateKey, {
		password: env.KEY_PASSPHRASE,
	});
	return { certificatePem: certificate.pem, encryptedKeyPem };
}

function storedKeyFor(fixture: X509Fixture, keyId: string, fingerprint: string, algorithm: string): StoredX509Key {
	return StoredX509KeySchema.parse({
		type: "x509",
		keyId,
		privateKeyPem: fixture.encryptedKeyPem,
		certificatePem: fixture.certificatePem,
		fingerprint,
		createdAt: new Date().toISOString(),
		algorithm,
	});
}

async function makeRequest(path: string, options: RequestInit = {}): Promise<Response> {
	const ctx = createExecutionContext();
	const response = await app.fetch(new Request(`http://localhost${path}`, options), env, ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

async function adminRequest(path: string, options: RequestInit = {}): Promise<Response> {
	return makeRequest(`/admin${path}`, {
		...options,
		headers: {
			Authorization: `Bearer ${env.ADMIN_TOKEN}`,
			"Content-Type": "application/json",
			...options.headers,
		},
	});
}

describe("X.509 signing utilities", () => {
	let fixture: X509Fixture;

	beforeAll(async () => {
		fixture = await generateX509Fixture("x509-test-signer");
	});

	it("validates key material and reports metadata", async () => {
		const info = await parseAndValidateX509Key(fixture.encryptedKeyPem, fixture.certificatePem, env.KEY_PASSPHRASE);

		expect(info.fingerprint).toMatch(/^[A-F0-9]{40}$/);
		expect(info.algorithm).toBe("ECDSA P-256");
		expect(info.subject).toBe("x509-test-signer");
	});

	it("rejects a private key that does not match the certificate", async () => {
		const other = await generateX509Fixture("some-other-signer");

		await expect(
			parseAndValidateX509Key(fixture.encryptedKeyPem, other.certificatePem, env.KEY_PASSPHRASE),
		).rejects.toThrow("does not match");
	});

	it("rejects a wrong passphrase", async () => {
		await expect(
			parseAndValidateX509Key(fixture.encryptedKeyPem, fixture.certificatePem, "wrong-passphrase"),
		).rejects.toThrow();
	});

	it("produces a detached PKCS#7 signature that verifies against the commit data", async () => {
		const info = await parseAndValidateX509Key(fixture.encryptedKeyPem, fixture.certificatePem, env.KEY_PASSPHRASE);
		const storedKey = storedKeyFor(fixture, "A1B2C3D4E5F60001", info.fingerprint, info.algorithm);
		const commitData = "tree 29ff16c9c14e2652b22f8b78bb08a5a07930c147\nauthor Test <t@t> 0 +0000\n\nmsg";

		const { signature } = await signCommitDataX509(commitData, storedKey, env.KEY_PASSPHRASE);

		expect(signature).toContain("-----BEGIN PKCS7-----");

		// Detached: content must not be embedded
		const parsed = parsePkcs7SignedDataPem(signature);
		expect(parsed.ok).toBe(true);

		// Without external content, verification must fail with the typed code
		const withoutContent = await verifyPkcs7SignedData(signature, {});
		expect(withoutContent.ok).toBe(false);

		// With the right content it verifies
		const verified = await verifyPkcs7SignedData(signature, {
			content: new TextEncoder().encode(commitData),
		});
		expect(verified.ok).toBe(true);

		// With tampered content it fails
		const tampered = await verifyPkcs7SignedData(signature, {
			content: new TextEncoder().encode(`${commitData} `),
		});
		expect(tampered.ok).toBe(false);
	});

	it("accepts a plain (unencrypted) PKCS#8 private key", async () => {
		const { certificate, keyPair } = await createSelfSignedCertificate({
			subject: { commonName: "plain-key-signer" },
			algorithm: { kind: "ecdsa", curve: "P-256" },
		});
		const plainKeyPem = await keyPair.exportPkcs8Pem();

		const info = await parseAndValidateX509Key(plainKeyPem, certificate.pem, env.KEY_PASSPHRASE);
		expect(info.subject).toBe("plain-key-signer");

		const storedKey = StoredX509KeySchema.parse({
			type: "x509",
			keyId: "A1B2C3D4E5F60003",
			privateKeyPem: plainKeyPem,
			certificatePem: certificate.pem,
			fingerprint: info.fingerprint,
			createdAt: new Date().toISOString(),
			algorithm: info.algorithm,
		});
		const { signature } = await signCommitDataX509("plain key commit", storedKey, env.KEY_PASSPHRASE);
		const verified = await verifyPkcs7SignedData(signature, {
			content: new TextEncoder().encode("plain key commit"),
		});
		expect(verified.ok).toBe(true);
	});

	it("describes RSA keys by modulus length", async () => {
		const { certificate, keyPair } = await createSelfSignedCertificate({
			subject: { commonName: "rsa-signer" },
			algorithm: { kind: "rsa", modulusLength: 2048 },
		});
		const keyPem = await exportEncryptedPkcs8Pem(keyPair.privateKey, {
			password: env.KEY_PASSPHRASE,
		});

		const info = await parseAndValidateX509Key(keyPem, certificate.pem, env.KEY_PASSPHRASE);
		expect(info.algorithm).toContain("2048");
	});

	it("falls back to 'unknown' when the certificate has no common name", async () => {
		const { certificate, keyPair } = await createSelfSignedCertificate({
			subject: { organization: "No CN Corp" },
			algorithm: { kind: "ecdsa", curve: "P-256" },
		});
		const keyPem = await exportEncryptedPkcs8Pem(keyPair.privateKey, {
			password: env.KEY_PASSPHRASE,
		});

		const info = await parseAndValidateX509Key(keyPem, certificate.pem, env.KEY_PASSPHRASE);
		expect(info.subject).toBe("unknown");
	});

	it("describes Ed25519 keys by name alone", async () => {
		const { certificate, keyPair } = await createSelfSignedCertificate({
			subject: { commonName: "ed25519-signer" },
			algorithm: { kind: "ed25519" },
		});
		const keyPem = await exportEncryptedPkcs8Pem(keyPair.privateKey, {
			password: env.KEY_PASSPHRASE,
		});

		const info = await parseAndValidateX509Key(keyPem, certificate.pem, env.KEY_PASSPHRASE);
		expect(info.algorithm).toBe("Ed25519");
	});

	it("embeds additional chain certificates when chainPem is present", async () => {
		const info = await parseAndValidateX509Key(fixture.encryptedKeyPem, fixture.certificatePem, env.KEY_PASSPHRASE);
		const chained = StoredX509KeySchema.parse({
			type: "x509",
			keyId: "A1B2C3D4E5F60002",
			privateKeyPem: fixture.encryptedKeyPem,
			certificatePem: fixture.certificatePem,
			chainPem: fixture.certificatePem,
			fingerprint: info.fingerprint,
			createdAt: new Date().toISOString(),
			algorithm: info.algorithm,
		});

		const { signature } = await signCommitDataX509("chained commit", chained, env.KEY_PASSPHRASE);
		const verified = await verifyPkcs7SignedData(signature, {
			content: new TextEncoder().encode("chained commit"),
		});
		expect(verified.ok).toBe(true);
	});
});

describe("X.509 admin endpoints", () => {
	let fixture: X509Fixture;

	beforeAll(async () => {
		fixture = await generateX509Fixture("x509-admin-test");
	});

	beforeEach(() => {
		vi.spyOn(env.JWKS_CACHE, "get").mockResolvedValue(null as unknown as Map<string, unknown>);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("uploads an X.509 key and returns its metadata", async () => {
		const response = await adminRequest("/keys/x509", {
			method: "POST",
			body: JSON.stringify({
				keyId: "B1B2C3D4E5F60001",
				privateKeyPem: fixture.encryptedKeyPem,
				certificatePem: fixture.certificatePem,
			}),
		});

		expect(response.status).toBe(201);
		const body = await parseJson<{
			success: boolean;
			keyId: string;
			fingerprint: string;
			algorithm: string;
			subject: string;
		}>(response);
		expect(body.success).toBe(true);
		expect(body.keyId).toBe("B1B2C3D4E5F60001");
		expect(body.fingerprint).toMatch(/^[A-F0-9]{40}$/);
		expect(body.algorithm).toBe("ECDSA P-256");
		expect(body.subject).toBe("x509-admin-test");
	});

	it("serves the certificate as the public material", async () => {
		await adminRequest("/keys/x509", {
			method: "POST",
			body: JSON.stringify({
				keyId: "B1B2C3D4E5F60002",
				privateKeyPem: fixture.encryptedKeyPem,
				certificatePem: fixture.certificatePem,
			}),
		});

		const response = await adminRequest("/keys/B1B2C3D4E5F60002/public");

		expect(response.status).toBe(200);
		expect(response.headers.get("Content-Type")).toContain("application/pem-certificate-chain");
		expect(await response.text()).toContain("-----BEGIN CERTIFICATE-----");
	});

	it("rejects an upload whose key does not match the certificate", async () => {
		const other = await generateX509Fixture("mismatched-signer");

		const response = await adminRequest("/keys/x509", {
			method: "POST",
			body: JSON.stringify({
				keyId: "B1B2C3D4E5F60003",
				privateKeyPem: fixture.encryptedKeyPem,
				certificatePem: other.certificatePem,
			}),
		});

		expect(response.status).toBe(500);
		const body = await parseJson<{ code: string }>(response);
		expect(body.code).toBe("KEY_UPLOAD_ERROR");
	});

	it("rejects a structurally invalid upload body", async () => {
		const response = await adminRequest("/keys/x509", {
			method: "POST",
			body: JSON.stringify({ keyId: "B1B2C3D4E5F60004", privateKeyPem: "not a pem" }),
		});

		expect(response.status).toBe(400);
	});

	it("returns 500 when key storage fails", async () => {
		vi.spyOn(env.KEY_STORAGE, "get").mockReturnValue({
			fetch: async () => new Response(JSON.stringify({ error: "Storage error" }), { status: 500 }),
		} as unknown as DurableObjectStub);

		const response = await adminRequest("/keys/x509", {
			method: "POST",
			body: JSON.stringify({
				keyId: "B1B2C3D4E5F60005",
				privateKeyPem: fixture.encryptedKeyPem,
				certificatePem: fixture.certificatePem,
			}),
		});

		expect(response.status).toBe(500);
		const body = await parseJson<{ error: string }>(response);
		expect(body.error).toBe("Storage error");
	});

	it("accepts an upload with a certificate chain", async () => {
		const response = await adminRequest("/keys/x509", {
			method: "POST",
			body: JSON.stringify({
				keyId: "B1B2C3D4E5F60007",
				privateKeyPem: fixture.encryptedKeyPem,
				certificatePem: fixture.certificatePem,
				chainPem: fixture.certificatePem,
			}),
		});

		expect(response.status).toBe(201);
	});

	it("uses the fallback message when storage fails without detail", async () => {
		vi.spyOn(env.KEY_STORAGE, "get").mockReturnValue({
			fetch: async () => new Response(JSON.stringify({}), { status: 500 }),
		} as unknown as DurableObjectStub);

		const response = await adminRequest("/keys/x509", {
			method: "POST",
			body: JSON.stringify({
				keyId: "B1B2C3D4E5F60006",
				privateKeyPem: fixture.encryptedKeyPem,
				certificatePem: fixture.certificatePem,
			}),
		});

		expect(response.status).toBe(500);
		const body = await parseJson<{ error: string }>(response);
		expect(body.error).toBe("Failed to store key");
	});
});

describe("X.509 sign route", () => {
	let fixture: X509Fixture;
	let oidcPrivateKey: CryptoKey;
	let oidcPublicKey: CryptoKey;
	const issuer = "https://token.actions.githubusercontent.com";
	const kid = "x509-test-key";

	beforeAll(async () => {
		fixture = await generateX509Fixture("x509-sign-test");
		const keys = await jose.generateKeyPair("ES256");
		oidcPrivateKey = keys.privateKey;
		oidcPublicKey = keys.publicKey;
	});

	beforeEach(() => {
		vi.resetAllMocks();
		vi.spyOn(env.JWKS_CACHE, "get").mockResolvedValue(null as unknown as Map<string, unknown>);
	});

	async function setupJWKSMock() {
		const jwk = await jose.exportJWK(oidcPublicKey);
		jwk.kid = kid;
		jwk.use = "sig";

		x509FetchMock.mockImplementation(async (url: string) => {
			if (url === `${issuer}/.well-known/openid-configuration`) {
				return new Response(JSON.stringify({ jwks_uri: `${issuer}/jwks` }));
			}
			if (url === `${issuer}/jwks`) {
				return new Response(JSON.stringify({ keys: [jwk] }));
			}
			return new Response("Not Found", { status: 404 });
		});
	}

	async function createToken(): Promise<string> {
		return new jose.SignJWT({
			iss: issuer,
			sub: "repo:user/repo:ref:refs/heads/main",
			aud: "gpg-signing-service",
		})
			.setProtectedHeader({ alg: "ES256", kid })
			.setIssuedAt()
			.setExpirationTime("1h")
			.sign(oidcPrivateKey);
	}

	it("falls back to 'Key not found' when storage errors without detail", async () => {
		await setupJWKSMock();
		const token = await createToken();

		vi.spyOn(env.KEY_STORAGE, "get").mockReturnValue({
			fetch: async () => new Response(JSON.stringify({}), { status: 500 }),
		} as unknown as DurableObjectStub);

		const response = await makeRequest("/sign?keyId=C1B2C3D4E5F60002", {
			method: "POST",
			headers: { Authorization: `Bearer ${token}` },
			body: "some commit data",
		});

		expect(response.status).toBe(404);
		const body = await parseJson<{ error: string }>(response);
		expect(body.error).toBe("Key not found");
	});

	it("signs commit data with a stored X.509 key (detached PKCS#7)", async () => {
		await setupJWKSMock();
		await adminRequest("/keys/x509", {
			method: "POST",
			body: JSON.stringify({
				keyId: "C1B2C3D4E5F60001",
				privateKeyPem: fixture.encryptedKeyPem,
				certificatePem: fixture.certificatePem,
			}),
		});
		const token = await createToken();
		const commitData = "tree 29ff16c9c14e2652b22f8b78bb08a5a07930c147\nx509 route commit";

		const response = await makeRequest("/sign?keyId=C1B2C3D4E5F60001", {
			method: "POST",
			headers: { Authorization: `Bearer ${token}` },
			body: commitData,
		});

		expect(response.status).toBe(200);
		const signature = await response.text();
		expect(signature).toContain("-----BEGIN PKCS7-----");

		const verified = await verifyPkcs7SignedData(signature, {
			content: new TextEncoder().encode(commitData),
		});
		expect(verified.ok).toBe(true);
	});
});
