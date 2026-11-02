import { type JsonObject, signJwt } from "micro509/jose";

/** An RS256 signing key pair for minting OIDC test tokens. */
export interface TestKeyPair {
	privateKey: CryptoKey;
	publicKey: CryptoKey;
}

/** A public key as a JWKS entry; tests set `kid` and `use` before publishing it. */
export type TestJwk = JsonWebKey & { kid?: string; use?: string };

/** A fresh 2048-bit RSASSA-PKCS1-v1_5 SHA-256 key pair, the only kind the OIDC middleware verifies. */
export async function generateTestKeyPair(): Promise<TestKeyPair> {
	const pair = await crypto.subtle.generateKey(
		{ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
		true,
		["sign", "verify"],
	);
	if (!("privateKey" in pair)) {
		throw new Error("RSA key generation returned a single key");
	}
	return { privateKey: pair.privateKey, publicKey: pair.publicKey };
}

/** The public key as a JWK. */
export async function exportTestJwk(publicKey: CryptoKey): Promise<TestJwk> {
	const exported = await crypto.subtle.exportKey("jwk", publicKey);
	if (exported instanceof ArrayBuffer) {
		throw new Error("JWK export returned raw bytes");
	}
	return exported;
}

/** `"1h"`, `"-1h"`, `"30m"` or `"45s"` relative to now, or an absolute epoch second. */
type TimeInput = string | number;

function epochSeconds(input: TimeInput, now: number): number {
	if (typeof input === "number") {
		return input;
	}
	const match = /^(-?\d+)([smhd])$/.exec(input);
	if (!match?.[1] || !match[2]) {
		throw new Error(`unsupported time span: ${input}`);
	}
	const unit = { s: 1, m: 60, h: 3600, d: 86400 }[match[2]];
	if (unit === undefined) {
		throw new Error(`unsupported time unit: ${input}`);
	}
	return now + Number(match[1]) * unit;
}

function base64url(text: string): string {
	return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * A JWT builder with the call shape of jose's `SignJWT`.
 *
 * RS256 tokens carry a real micro509 signature. Any other `alg` gets a
 * placeholder signature: the middleware refuses those on the header before a
 * signature is ever checked.
 */
export class TestJwt {
	private readonly claims: Record<string, unknown>;
	private header: { alg: string; kid?: string } = { alg: "RS256" };
	private readonly now = Math.floor(Date.now() / 1000);

	constructor(claims: object) {
		this.claims = { ...claims };
	}

	setProtectedHeader(header: { alg: string; kid?: string }): this {
		this.header = header;
		return this;
	}

	setIssuedAt(at?: TimeInput): this {
		this.claims.iat = at === undefined ? this.now : epochSeconds(at, this.now);
		return this;
	}

	setExpirationTime(at: TimeInput): this {
		this.claims.exp = epochSeconds(at, this.now);
		return this;
	}

	setNotBefore(at: TimeInput): this {
		this.claims.nbf = epochSeconds(at, this.now);
		return this;
	}

	async sign(privateKey: CryptoKey): Promise<string> {
		const claims: JsonObject = JSON.parse(JSON.stringify(this.claims));
		if (this.header.alg === "RS256") {
			return signJwt({
				privateKey,
				algorithm: "RS256",
				claims,
				...(this.header.kid !== undefined && { header: { kid: this.header.kid } }),
			});
		}
		const header = base64url(JSON.stringify(this.header));
		const payload = base64url(JSON.stringify(claims));
		return `${header}.${payload}.${base64url("unsigned")}`;
	}
}
