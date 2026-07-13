/**
 * X.509 / PKCS#7 signing utilities (git `gpg.format=x509` compatible)
 *
 * Uses micro509 for all PKI operations. Signatures are detached CMS
 * SignedData structures — git stores the PKCS#7 blob in the commit header
 * and supplies the commit bytes externally at verification time.
 */

import {
	certificateFingerprint,
	certificateMatchesPrivateKey,
	createPkcs7SignedData,
	importEncryptedPkcs8PemOrThrow,
	importPkcs8PemOrThrow,
	parseCertificatePemOrThrow,
	splitPemBlocksOrThrow,
	unwrap,
} from "micro509";
import type { StoredX509Key } from "#schemas/keys";
import type { KeyFingerprint } from "#types";
import { createKeyFingerprint } from "#types";

/** Result of validating an uploaded X.509 key pair */
export interface X509KeyInfo {
	fingerprint: KeyFingerprint;
	algorithm: string;
	subject: string;
}

/**
 * Import a PKCS#8 private key PEM, transparently handling the
 * PBES2-encrypted form. micro509 infers the key algorithm from the
 * PrivateKeyInfo AlgorithmIdentifier.
 */
function importX509PrivateKey(privateKeyPem: string, passphrase: string): Promise<CryptoKey> {
	if (privateKeyPem.includes("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
		return importEncryptedPkcs8PemOrThrow(privateKeyPem, passphrase);
	}
	return importPkcs8PemOrThrow(privateKeyPem);
}

/** Human-readable algorithm description derived from a CryptoKey */
function describeKeyAlgorithm(key: CryptoKey): string {
	const algorithm = key.algorithm;
	if ("namedCurve" in algorithm && typeof algorithm.namedCurve === "string") {
		return `${algorithm.name} ${algorithm.namedCurve}`;
	}
	if ("modulusLength" in algorithm && typeof algorithm.modulusLength === "number") {
		return `${algorithm.name} ${algorithm.modulusLength}`;
	}
	return algorithm.name;
}

/**
 * Validate an uploaded X.509 signing key:
 * - private key imports (with the service passphrase when encrypted)
 * - certificate parses
 * - private key matches the certificate (SPKI DER comparison)
 *
 * Throws on any mismatch; returns display metadata on success.
 */
export async function parseAndValidateX509Key(
	privateKeyPem: string,
	certificatePem: string,
	passphrase: string,
): Promise<X509KeyInfo> {
	const privateKey = await importX509PrivateKey(privateKeyPem, passphrase);
	const certificate = parseCertificatePemOrThrow(certificatePem);

	if (!(await certificateMatchesPrivateKey(certificate, privateKey))) {
		throw new Error("Private key does not match certificate public key");
	}

	// SHA-1 is the classic X.509 fingerprint form; its 40 hex chars match the
	// service-wide FingerprintSchema shared with PGP fingerprints.
	const fingerprint = await certificateFingerprint(certificate, "SHA-1");

	return {
		fingerprint: createKeyFingerprint(fingerprint.hex.toUpperCase()),
		algorithm: describeKeyAlgorithm(privateKey),
		subject: certificate.subject.values.commonName ?? "unknown",
	};
}

/**
 * Produce a detached PKCS#7/CMS signature over commit data,
 * PEM-armored — the artifact git expects from an x509 signing program.
 */
export async function signCommitDataX509(
	commitData: string,
	storedKey: StoredX509Key,
	passphrase: string,
): Promise<{ signature: string }> {
	const privateKey = await importX509PrivateKey(storedKey.privateKeyPem, passphrase);

	const additionalCertificates = storedKey.chainPem
		? splitPemBlocksOrThrow(storedKey.chainPem)
				.filter((block) => block.label === "CERTIFICATE")
				.map((block) => block.bytes)
		: undefined;

	const result = unwrap(
		await createPkcs7SignedData({
			content: new TextEncoder().encode(commitData),
			signers: [{ certificate: storedKey.certificatePem, privateKey }],
			...(additionalCertificates !== undefined && { additionalCertificates }),
			detached: true,
		}),
	);

	return { signature: result.pem };
}
