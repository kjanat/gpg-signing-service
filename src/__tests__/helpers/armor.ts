/**
 * Armor markers for fixtures.
 *
 * The definitions live in `#utils/armor` — production needs them for the same
 * reason the suites do, and one definition means a fixture cannot drift from
 * the constant the code under test compares against. See that file for why
 * spelling an armor header out in a tracked file is a hazard rather than a
 * nuisance.
 */

export {
	armorMarker as armor,
	CERTIFICATE_BEGIN,
	CERTIFICATE_END,
	EC_PRIVATE_BEGIN,
	EC_PRIVATE_END,
	OPENSSH_PRIVATE_BEGIN,
	OPENSSH_PRIVATE_END,
	PGP_PRIVATE_BEGIN,
	PGP_PRIVATE_END,
	PGP_PUBLIC_BEGIN,
	PGP_PUBLIC_END,
	PGP_SIGNATURE_BEGIN,
	PGP_SIGNATURE_END,
	PKCS8_ENCRYPTED_BEGIN,
	PKCS8_ENCRYPTED_END,
	PKCS8_PRIVATE_BEGIN,
	PKCS8_PRIVATE_END,
	RSA_PRIVATE_BEGIN,
	RSA_PRIVATE_END,
} from "#utils/armor";

import { armorMarker } from "#utils/armor";

/** Wrap `body` in the armor pair for `label`. */
export function armored(label: string, body: string): string {
	return `${armorMarker("BEGIN", label)}\n${body}\n${armorMarker("END", label)}`;
}
