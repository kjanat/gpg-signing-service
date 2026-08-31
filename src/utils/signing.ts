import * as openpgp from "openpgp";
import type { StoredKey } from "#schemas/keys";
import type { ArmoredPrivateKey, ParsedKeyInfo, SigningResult } from "#types";
import { createArmoredPrivateKey, createKeyFingerprint, createKeyId } from "#types";
import { DecryptedKeyCache } from "#utils/key-cache";

// Re-export types for convenience
export type { ParsedKeyInfo, SigningResult };

// Module-level cache instance for decrypted keys
// Safe in Workers: each isolate has its own instance
const decryptedKeyCache = new DecryptedKeyCache();

/**
 * Produce an ASCII-armored *binary* detached OpenPGP signature (signature type
 * 0x00) over the exact bytes of `commitData` — the artifact Git expects from a
 * `gpg.program`. `commitData` is the unsigned commit object as received; it is
 * UTF-8 encoded and signed without any line-ending canonicalization.
 */
export async function signCommitData(
	commitData: string,
	storedKey: StoredKey,
	passphrase: string,
): Promise<SigningResult> {
	// Try to get cached decrypted key first
	let decryptedKey = decryptedKeyCache.get(storedKey.keyId);

	if (!decryptedKey) {
		// Cache miss: parse and decrypt the key
		const privateKey = await openpgp.readPrivateKey({
			armoredKey: storedKey.armoredPrivateKey,
		});

		// Decrypt if passphrase protected
		decryptedKey = privateKey;
		if (!privateKey.isDecrypted()) {
			decryptedKey = await openpgp.decryptKey({ privateKey, passphrase });
		}

		// Cache the decrypted key for future requests
		decryptedKeyCache.set(storedKey.keyId, decryptedKey);
	}

	// Sign the raw commit bytes, never `{ text }`. A text message makes openpgp.js
	// emit a canonical-text signature (sigclass 0x01), which hashes the payload
	// with every line ending rewritten to CRLF. Git signs with `gpg -bsa` and no
	// `--textmode`, so a real Git signature is sigclass 0x00 over the commit
	// object byte for byte. The difference is not cosmetic: under 0x01 a commit
	// ending its lines in LF and the same commit ending them in CRLF hash
	// identically, so one signature stays valid across two distinct commit
	// objects. 0x00 binds the signature to exactly these bytes.
	const message = await openpgp.createMessage({
		binary: new TextEncoder().encode(commitData),
	});

	// Create detached signature
	const signature = await openpgp.sign({
		message,
		signingKeys: decryptedKey,
		detached: true,
		format: "armored",
	});

	return {
		signature: signature as string,
		keyId: storedKey.keyId,
		algorithm: storedKey.algorithm,
		fingerprint: storedKey.fingerprint,
	};
}

/**
 * Does `armoredSignature` verify over `payload` under `armoredPublicKey`?
 *
 * Used on both sides of the webhook signing path, and both uses are
 * load-bearing:
 *
 * - **Before rewriting.** A commit that already carries a signature this key
 *   produces is left alone. Asking whether the signature *verifies*, rather
 *   than whether it names our key id, is what makes that check honest — a key
 *   id in an armor header is a claim, and a commit carrying an invalid
 *   signature that names our key would otherwise be skipped forever.
 * - **After signing and before creating anything.** Every signature this
 *   service produces is checked against its own public key before the commit
 *   object is created and long before any ref moves. That is what closes the
 *   loop: a push this service makes carries signatures that verify, so the
 *   delivery it provokes finds nothing to sign and stops. A signature that
 *   silently failed to verify would make the same push arrive, be rewritten,
 *   and arrive again.
 *
 * Never throws. openpgp reports a failed verification by rejecting the promise
 * on `verified`, and there is no useful distinction here between "the signature
 * is wrong" and "the signature is not a signature" — both mean *do not treat
 * this as signed*.
 */
export async function verifyDetachedSignature(
	payload: string,
	armoredSignature: string,
	armoredPublicKey: string,
): Promise<boolean> {
	try {
		const verificationKeys = await openpgp.readKey({ armoredKey: armoredPublicKey });
		const signature = await openpgp.readSignature({ armoredSignature });
		// Binary, matching `signCommitData`: a text message would verify a
		// canonical-text signature over line endings this payload does not have.
		const message = await openpgp.createMessage({ binary: new TextEncoder().encode(payload) });

		const result = await openpgp.verify({ message, signature, verificationKeys, expectSigned: false });
		const first = result.signatures[0];
		if (first === undefined) {
			return false;
		}

		return await first.verified;
	} catch {
		return false;
	}
}

/**
 * The lowercase email addresses this key carries a user ID for.
 *
 * The commit-signing path signs only commits whose *committer* is one of these,
 * for the reason `.github/scripts/sign-commits.py` does: attaching this key to
 * a commit made by somebody else asserts an authorship that is not true, and
 * rewriting it strips whatever signature that person had. A key with no
 * addressed user ID signs nothing, which is the fail-closed reading of an empty
 * set rather than a special case.
 */
export async function keyIdentityEmails(armoredKey: string): Promise<Set<string>> {
	const key = await openpgp.readKey({ armoredKey });

	const emails = new Set<string>();
	for (const userId of key.getUserIDs()) {
		const match = /<([^<>]+)>\s*$/.exec(userId);
		if (match?.[1]) {
			emails.add(match[1].toLowerCase());
		}
	}

	return emails;
}

export async function parseAndValidateKey(armoredKey: string, passphrase?: string): Promise<ParsedKeyInfo> {
	const privateKey = await openpgp.readPrivateKey({ armoredKey });

	// Verify we can decrypt if passphrase provided
	if (passphrase && !privateKey.isDecrypted()) {
		await openpgp.decryptKey({ privateKey, passphrase });
	}

	const keyPacket = privateKey.keyPacket;
	const fingerprint = createKeyFingerprint(privateKey.getFingerprint());
	const keyId = createKeyId(privateKey.getKeyID().toHex().toUpperCase());

	/**
	 * Get algorithm name
	 *
	 * @link https://datatracker.ietf.org/doc/html/rfc4880#section-9.1
	 */
	const algorithmMap: Record<number, string> = {
		1: "RSA", // RSA Encrypt or Sign
		2: "RSA-E", // RSA Encrypt-Only
		3: "RSA-S", // RSA Sign-Only
		16: "Elgamal", // Encrypt-Only
		17: "DSA", // Digital Signature Algorithm
		18: "ECDH", // Reserved for Elliptic Curve
		19: "ECDSA", // Reserved for ECDSA
		22: "EdDSA",
	};

	const algorithm = algorithmMap[keyPacket.algorithm] || `Unknown(${keyPacket.algorithm})`;

	// Get user ID
	const userIds = privateKey.getUserIDs();
	const userId = userIds[0] || "Unknown";

	return { keyId, fingerprint, algorithm, userId };
}

export async function extractPublicKey(armoredPrivateKey: ArmoredPrivateKey | string): Promise<string> {
	const privateKey = await openpgp.readPrivateKey({
		armoredKey: armoredPrivateKey,
	});
	return privateKey.toPublic().armor();
}

/**
 * Create a StoredKey from raw input data
 */
export function createStoredKey(
	armoredPrivateKey: string,
	keyId: string,
	fingerprint: string,
	algorithm: string,
): StoredKey {
	return {
		armoredPrivateKey: createArmoredPrivateKey(armoredPrivateKey),
		keyId: createKeyId(keyId),
		fingerprint: createKeyFingerprint(fingerprint),
		createdAt: new Date().toISOString(),
		algorithm,
	};
}

/**
 * Invalidate a specific key from the decrypted key cache
 * Call this when a key is rotated or deleted
 */
export function invalidateKeyCache(keyId: string): void {
	decryptedKeyCache.invalidate(keyId);
}

/**
 * Clear the entire decrypted key cache
 * Call this on service restart or security events
 */
export function clearKeyCache(): void {
	decryptedKeyCache.clear();
}

/**
 * Get cache statistics for monitoring
 */
export function getKeyCacheStats(): { size: number; ttl: number } {
	return decryptedKeyCache.stats();
}
