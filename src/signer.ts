import { WorkerEntrypoint } from "cloudflare:workers";
import * as openpgp from "openpgp";
import type { StoredKey } from "#schemas/keys";
import { AnyStoredKeySchema, isX509Key } from "#schemas/keys";
import type { Env } from "#types";
import { createIdentity } from "#types";
import { logAuditEvent } from "#utils/audit";
import { fetchKeyStorage, fetchRateLimiter } from "#utils/durable-objects";
import { signCommitData } from "#utils/signing";

export const BINDING_ISSUER = "service-binding";

export interface SigningIdentity {
	publicKey: string;
	userId: string;
}

/** Only Workers the operator binds to this entrypoint can call it. */
export class Signer extends WorkerEntrypoint<Env> {
	async identity(): Promise<SigningIdentity> {
		const key = await openpgp.readPrivateKey({ armoredKey: (await this.key()).armoredPrivateKey });
		const { user } = await key.getPrimaryUser();
		const userId = user.userID?.userID;
		if (!userId) throw new Error("Signing key has no user ID");
		return { publicKey: key.toPublic().armor(), userId };
	}

	async sign(data: string, caller: string): Promise<string> {
		const limited = await fetchRateLimiter(this.env, createIdentity(BINDING_ISSUER, caller));
		if (!limited.ok) throw new Error(`Signing refused by the rate limiter: HTTP ${limited.status}`);
		const key = await this.key();
		const entry = {
			requestId: crypto.randomUUID(),
			action: "sign",
			issuer: BINDING_ISSUER,
			subject: caller,
			keyId: key.keyId,
		} as const;
		try {
			const { signature } = await signCommitData(data, key, this.env.KEY_PASSPHRASE);
			await logAuditEvent(this.env.AUDIT_DB, {
				...entry,
				success: true,
				metadata: JSON.stringify({ dataLength: data.length }),
			});
			return signature;
		} catch (error) {
			await logAuditEvent(this.env.AUDIT_DB, { ...entry, success: false, errorCode: "SIGN_ERROR" });
			throw error;
		}
	}

	private async key(): Promise<StoredKey> {
		const response = await fetchKeyStorage(this.env, `/get-key?keyId=${encodeURIComponent(this.env.KEY_ID)}`);
		if (!response.ok) throw new Error(`Key ${this.env.KEY_ID} not found`);
		const stored = AnyStoredKeySchema.parse(await response.json());
		if (isX509Key(stored)) throw new Error(`Key ${this.env.KEY_ID} is not a PGP key`);
		return stored;
	}
}
