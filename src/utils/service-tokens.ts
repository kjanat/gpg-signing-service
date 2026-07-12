/**
 * Service tokens: the "one secret in any CI" auth path. A token is minted
 * through the admin API, shown once, and stored only as a SHA-256 hash. Any
 * CI system presents it as `Authorization: Bearer gst_...` — no OIDC issuer
 * required. Each token carries an optional key-id allowlist.
 */

import { logger } from "~/utils/logger";

/** Prefix distinguishing service tokens from OIDC JWTs in the auth header. */
export const SERVICE_TOKEN_PREFIX = "gst_";

/** A verified token's identity and signing policy. */
export interface ServiceTokenPolicy {
  id: string;
  name: string;
  /** Key ids this token may sign with; null means every key. */
  allowedKeyIds: string[] | null;
}

interface ServiceTokenRow {
  id: string;
  name: string;
  key_ids: string;
  expires_at: string | null;
  revoked_at: string | null;
}

/** SHA-256 hex digest of a token string. */
export async function hashToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/** Generate a new token: `gst_` + 256 bits of base64url entropy. */
export function generateToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const base64 = btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
  return `${SERVICE_TOKEN_PREFIX}${base64}`;
}

/** Persist a freshly minted token. Returns the stored row's id. */
export async function insertServiceToken(
  db: D1Database,
  input: {
    name: string;
    token: string;
    keyIds: string[];
    expiresAt: string | null;
  },
): Promise<string> {
  const id = crypto.randomUUID();
  await db
    .prepare(
      `INSERT INTO service_tokens (id, name, token_hash, key_ids, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      id,
      input.name,
      await hashToken(input.token),
      input.keyIds.join(","),
      new Date().toISOString(),
      input.expiresAt,
    )
    .run();
  return id;
}

/**
 * Verify a presented token: hash lookup, revocation and expiry checks.
 * Returns the token's policy, or null when the token is not acceptable.
 */
export async function verifyServiceToken(
  db: D1Database,
  token: string,
): Promise<ServiceTokenPolicy | null> {
  const row = await db
    .prepare(
      `SELECT id, name, key_ids, expires_at, revoked_at
       FROM service_tokens WHERE token_hash = ?`,
    )
    .bind(await hashToken(token))
    .first<ServiceTokenRow>();

  if (!row) {
    return null;
  }
  if (row.revoked_at) {
    return null;
  }
  if (row.expires_at && Date.parse(row.expires_at) < Date.now()) {
    return null;
  }

  // Best-effort usage stamp; a failed write must not block signing.
  try {
    await db
      .prepare("UPDATE service_tokens SET last_used_at = ? WHERE id = ?")
      .bind(new Date().toISOString(), row.id)
      .run();
  } catch (error) {
    logger.warn("Failed to stamp service token usage", {
      tokenId: row.id,
      error: error instanceof Error ? error.message : String(error),
    });
  }

  const keyIds = row.key_ids
    .split(",")
    .map((keyId) => keyId.trim())
    .filter((keyId) => keyId.length > 0);

  return {
    id: row.id,
    name: row.name,
    allowedKeyIds: keyIds.length > 0 ? keyIds : null,
  };
}

/** List all tokens (hashes never leave the database). */
export async function listServiceTokens(db: D1Database): Promise<
  {
    id: string;
    name: string;
    keyIds: string[] | null;
    createdAt: string;
    expiresAt: string | null;
    revokedAt: string | null;
    lastUsedAt: string | null;
  }[]
> {
  const { results } = await db
    .prepare(
      `SELECT id, name, key_ids, created_at, expires_at, revoked_at, last_used_at
       FROM service_tokens ORDER BY created_at DESC`,
    )
    .all<
      ServiceTokenRow & { created_at: string; last_used_at: string | null }
    >();

  return results.map((row) => {
    const keyIds = row.key_ids
      .split(",")
      .map((keyId) => keyId.trim())
      .filter((keyId) => keyId.length > 0);
    return {
      id: row.id,
      name: row.name,
      keyIds: keyIds.length > 0 ? keyIds : null,
      createdAt: row.created_at,
      expiresAt: row.expires_at,
      revokedAt: row.revoked_at,
      lastUsedAt: row.last_used_at,
    };
  });
}

/** Revoke a token by id. Returns false when the id is unknown. */
export async function revokeServiceToken(
  db: D1Database,
  id: string,
): Promise<boolean> {
  const result = await db
    .prepare(
      "UPDATE service_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
    )
    .bind(new Date().toISOString(), id)
    .run();
  return result.meta.changes > 0;
}
