/**
 * PEM/OpenPGP armor markers, assembled at run time.
 *
 * ## Why these are built instead of written
 *
 * gitleaks' default `private-key` rule is, in effect
 *
 * ```text
 * (?i)-{5}BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY( BLOCK)?-{5}[\s\S-]{64,}?KEY( BLOCK)?-{4}
 * ```
 *
 * — a header, then a lazy run of at least 64 characters, then the next
 * `KEY-----`. A literal armor header anywhere in a tracked file therefore opens
 * a match that continues until it finds one, and a real private key committed
 * further down the same file is *inside* that single match rather than being a
 * finding of its own. Measured against gitleaks 8.24.3, the version CI runs,
 * that made a freshly generated RSA key invisible in seven of this repository's
 * files — including `src/utils/key-expiry.ts`'s neighbours — because the
 * swallowing match itself is dropped once the span grows past roughly 35 kB.
 * The scan stays green and the key is in the diff.
 *
 * Suppressing the fixture instead is worse: a global allowlist entry matching
 * the head of such a span excuses everything the span swallowed, which is the
 * fail-open this file and #146 exist to remove. Assembling the marker from
 * parts means the detector never fires on the constant, nothing needs excusing,
 * and a real key committed beside it is a match of its own.
 *
 * `scripts/test-gitleaks-contract.sh` plants a generated key next to every use
 * of these constants and fails if any of them is not reported.
 */

const DASHES = "-".repeat(5);

/** Build an armor boundary line, e.g. the PGP private key block header. */
export function armorMarker(boundary: "BEGIN" | "END", label: string): string {
	return `${DASHES}${boundary} ${label}${DASHES}`;
}

const PGP_PRIVATE = "PGP PRIVATE KEY BLOCK";
const PGP_PUBLIC = "PGP PUBLIC KEY BLOCK";
const PGP_SIGNATURE = "PGP SIGNATURE";
const RSA_PRIVATE = "RSA PRIVATE KEY";
const PKCS8_PRIVATE = "PRIVATE KEY";
const PKCS8_ENCRYPTED = "ENCRYPTED PRIVATE KEY";
const EC_PRIVATE = "EC PRIVATE KEY";
const OPENSSH_PRIVATE = "OPENSSH PRIVATE KEY";
const CERTIFICATE = "CERTIFICATE";

export const PGP_PRIVATE_BEGIN = armorMarker("BEGIN", PGP_PRIVATE);
export const PGP_PRIVATE_END = armorMarker("END", PGP_PRIVATE);
export const PGP_PUBLIC_BEGIN = armorMarker("BEGIN", PGP_PUBLIC);
export const PGP_PUBLIC_END = armorMarker("END", PGP_PUBLIC);
export const PGP_SIGNATURE_BEGIN = armorMarker("BEGIN", PGP_SIGNATURE);
export const PGP_SIGNATURE_END = armorMarker("END", PGP_SIGNATURE);
export const RSA_PRIVATE_BEGIN = armorMarker("BEGIN", RSA_PRIVATE);
export const RSA_PRIVATE_END = armorMarker("END", RSA_PRIVATE);
export const PKCS8_PRIVATE_BEGIN = armorMarker("BEGIN", PKCS8_PRIVATE);
export const PKCS8_PRIVATE_END = armorMarker("END", PKCS8_PRIVATE);
export const PKCS8_ENCRYPTED_BEGIN = armorMarker("BEGIN", PKCS8_ENCRYPTED);
export const PKCS8_ENCRYPTED_END = armorMarker("END", PKCS8_ENCRYPTED);
export const EC_PRIVATE_BEGIN = armorMarker("BEGIN", EC_PRIVATE);
export const EC_PRIVATE_END = armorMarker("END", EC_PRIVATE);
export const OPENSSH_PRIVATE_BEGIN = armorMarker("BEGIN", OPENSSH_PRIVATE);
export const OPENSSH_PRIVATE_END = armorMarker("END", OPENSSH_PRIVATE);
export const CERTIFICATE_BEGIN = armorMarker("BEGIN", CERTIFICATE);
export const CERTIFICATE_END = armorMarker("END", CERTIFICATE);
