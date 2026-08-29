/**
 * Sign a payload with the service's own OpenPGP code path, outside a Worker.
 *
 * Used by `scripts/test-gnupg-interop.sh` so the interoperability check exercises
 * `signCommitData` itself rather than a re-implementation of it.
 *
 * Usage: bun scripts/gnupg-interop-sign.ts <armored-private-key> <payload-file>
 * Writes the ASCII-armored detached signature to stdout.
 */
import { readFileSync } from "node:fs";
import { createStoredKey, parseAndValidateKey, signCommitData } from "#utils/signing";

const [keyPath, payloadPath] = process.argv.slice(2);

if (!keyPath || !payloadPath) {
	console.error("usage: bun scripts/gnupg-interop-sign.ts <armored-private-key> <payload-file>");
	process.exit(2);
}

const armoredPrivateKey = readFileSync(keyPath, "utf8");
// The payload is read as UTF-8 because that is what `POST /sign` receives: Hono
// decodes the request body to a string before the signing code ever sees it.
const payload = readFileSync(payloadPath, "utf8");

const { keyId, fingerprint, algorithm } = await parseAndValidateKey(armoredPrivateKey, process.env.KEY_PASSPHRASE);
const storedKey = createStoredKey(armoredPrivateKey, keyId, fingerprint, algorithm);

const { signature } = await signCommitData(payload, storedKey, process.env.KEY_PASSPHRASE ?? "");

process.stdout.write(signature);
