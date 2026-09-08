/**
 * Armored private-key fixtures, assembled at run time.
 *
 * ## Why these are generated rather than committed
 *
 * #147: the block this replaces was not a fixture. It was one encrypted
 * secret-key packet belonging to the deployment's own signing key, copied
 * twelve times across four suites — twice with the four creation-time bytes
 * altered, which changes the derived fingerprint while leaving the S2K-encrypted
 * secret scalar and the public point byte-identical. A passphrase the repository
 * does not hold is what stood between that and a usable key, and a passphrase is
 * not a boundary a public test corpus should be leaning on.
 *
 * Not one of those twelve sites needed a key. Every one asserts on *shape*:
 * `ArmoredPrivateKeySchema` counts lines and characters, `createArmoredPrivateKey`
 * looks for its markers and a length, and the two route cases mock `openpgp`
 * into rejecting before it ever parses what it was handed. So the fixture only
 * has to be an armored block of realistic size, and this file builds one.
 *
 * ## Why the body is computed and not a literal
 *
 * A committed base64 blob would be the same hazard one rotation later: something
 * key-shaped in a tracked file, indistinguishable at a glance from the thing
 * that caused #147, and a fresh target for the entropy rules `#utils/armor`
 * already explains. Generating it means the source carries no high-entropy run
 * at all, and the scanner has nothing to excuse, which is #146's property A.
 * `scripts/key-material.py`, via `task test:key-material`, holds the narrower
 * line for the whole corpus: no tracked file may carry an OpenPGP key packet,
 * in base64 at any width, in raw bytes, or behind `\n`, `\+` or `\xNN` escapes.
 *
 * The generator is a Lehmer sequence rather than `crypto.getRandomValues`, so a
 * fixture is identical on every run and a failure reproduces from its seed.
 */

import { PGP_PRIVATE_BEGIN, PGP_PRIVATE_END } from "#utils/armor";

/** Lehmer / Park-Miller. Full period over `[1, 2^31 - 2]`, so a seed never dies. */
function advance(state: number): number {
	return (state * 48_271) % 0x7f_ff_ff_ff;
}

/**
 * `count` deterministic bytes from `seed`.
 *
 * Base64 of these is what stands in for key material. It has to survive the
 * schema's `^[A-Za-z0-9+/=]{1,76}$` line test, which real base64 does by
 * construction, and it must not be real — hence bytes rather than a hand-picked
 * alphabet, which is also how the file avoids spelling that alphabet out.
 */
function pseudoBytes(count: number, seed: number): Uint8Array {
	const bytes = new Uint8Array(count);
	let state = seed % 0x7f_ff_ff_ff || 1;
	for (let index = 0; index < count; index++) {
		state = advance(state);
		bytes[index] = state & 0xff;
	}
	return bytes;
}

/** Wrap `text` at `width`, the way armor bodies are wrapped. */
function wrap(text: string, width: number): string[] {
	const lines: string[] = [];
	for (let start = 0; start < text.length; start += width) {
		lines.push(text.slice(start, start + width));
	}
	return lines;
}

export interface ArmoredPrivateKeyFixtureOptions {
	/** Armor headers (`Version:`, `Comment:`) between the marker and the blank line. */
	headers?: readonly string[];
	/** Body lines at 64 characters. Eight is about an armored Ed25519 key. */
	lines?: number;
	/** Vary the body without changing its shape. Any non-zero integer. */
	seed?: number;
	/** The CRC-24 line, minus its `=`. Four base64 characters, per RFC 4880. */
	checksum?: string;
}

/**
 * An armored PGP private key block of realistic size, carrying no key.
 *
 * The default is ~600 characters: comfortably over `LIMITS.MIN_KEY_SIZE` (350,
 * an Ed25519 key) and far under `LIMITS.MAX_KEY_SIZE`, so it is a *valid* input
 * everywhere the suites need one to be.
 */
export function armoredPrivateKeyFixture(options: ArmoredPrivateKeyFixtureOptions = {}): string {
	const { headers = [], lines = 8, seed = 1, checksum = "aBc1" } = options;

	// 64 base64 characters is 48 bytes, and `btoa` pads the tail rather than
	// leaving a partial group, so the wrap lands on exact line boundaries.
	const bytes = pseudoBytes(lines * 48, seed);
	const body = wrap(btoa(String.fromCharCode(...bytes)), 64);
	const preamble = headers.length > 0 ? `${headers.join("\n")}\n` : "";

	return `${PGP_PRIVATE_BEGIN}\n${preamble}\n${body.join("\n")}\n=${checksum}\n${PGP_PRIVATE_END}`;
}

/**
 * The fixture the suites reach for when they just need "a valid armored key".
 *
 * Shared rather than re-derived per call site so that the twelve places #147
 * found cannot drift back into twelve separate blobs.
 */
export const VALID_ARMORED_PRIVATE_KEY = armoredPrivateKeyFixture();
