import type { MiddlewareHandler } from "hono";
import { createLocalJWKSet, type JWTPayload, jwtVerify } from "jose";
import type { Env, LegacyJWKSResponse, OIDCClaims, Variables } from "~/types";
import { createIdentity, HTTP, markClaimsAsValidated, TIME } from "~/types";
import { CACHE_TTL } from "~/utils/constants";
import { fetchWithTimeout } from "~/utils/fetch";
import { logger } from "~/utils/logger";

// OIDC validation middleware
export const oidcAuth: MiddlewareHandler<{
  Bindings: Env;
  Variables: Variables;
}> = async (c, next) => {
  const authHeader = c.req.header("Authorization");

  if (!authHeader?.startsWith("Bearer ")) {
    return c.json(
      { error: "Missing authorization header", code: "AUTH_MISSING" },
      401,
    );
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return c.json({ error: "Missing token" }, HTTP.Unauthorized);
  }

  try {
    const payload = await validateOIDCToken(token, c.env);
    const validatedClaims = markClaimsAsValidated(payload);

    // Store validated claims in context for downstream use
    c.set("oidcClaims", validatedClaims);
    c.set("identity", createIdentity(payload.iss, payload.sub));

    return next();
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid token";
    return c.json({ error: message, code: "AUTH_INVALID" }, HTTP.Unauthorized);
  }
};

// Admin token auth for management endpoints
export const adminAuth: MiddlewareHandler<{ Bindings: Env }> = async (
  c,
  next,
) => {
  const authHeader = c.req.header("Authorization");

  if (!authHeader?.startsWith("Bearer ")) {
    return c.json(
      { error: "Missing authorization header", code: "AUTH_MISSING" },
      401,
    );
  }

  const token = authHeader.slice(7);

  // Use constant-time comparison to prevent timing attacks
  const isValid = await timingSafeEqual(token, c.env.ADMIN_TOKEN);
  if (!isValid) {
    return c.json(
      { error: "Invalid admin token", code: "AUTH_INVALID" },
      HTTP.Unauthorized,
    );
  }

  return next();
};

// Constant-time string comparison to prevent timing attacks
async function timingSafeEqual(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const aBytes = encoder.encode(a);
  const bBytes = encoder.encode(b);

  // Pad shorter value to match longer length for constant-time comparison
  const maxLen = Math.max(aBytes.length, bBytes.length);
  const aPadded = new Uint8Array(maxLen);
  const bPadded = new Uint8Array(maxLen);
  aPadded.set(aBytes);
  bPadded.set(bBytes);

  // Now compare same-length arrays, then check if original lengths matched
  const bytesEqual = crypto.subtle.timingSafeEqual(aPadded, bPadded);
  const lengthsEqual = aBytes.length === bBytes.length;

  return bytesEqual && lengthsEqual;
}

// Allowed JWT signing algorithms
const ALLOWED_ALGORITHMS = ["RS256", "RS384", "RS512", "ES256", "ES384"];

async function validateOIDCToken(token: string, env: Env): Promise<OIDCClaims> {
  // Decode JWT header and payload (without verification first)
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    throw new Error("Invalid token format");
  }

  // Parse header and payload with explicit error handling
  let header: { kid: string; alg: string };
  let payload: OIDCClaims;
  try {
    header = JSON.parse(atob(parts[0])) as { kid: string; alg: string };
    payload = JSON.parse(atob(parts[1])) as OIDCClaims;
  } catch {
    throw new Error("Invalid token encoding");
  }

  // Validate algorithm against whitelist
  if (!ALLOWED_ALGORITHMS.includes(header.alg)) {
    throw new Error(`Algorithm not allowed: ${header.alg}`);
  }

  // Validate issuer
  const allowedIssuers = env.ALLOWED_ISSUERS.split(",");
  if (!allowedIssuers.includes(payload.iss)) {
    throw new Error(`Issuer not allowed: ${payload.iss}`);
  }

  // Check timing claims with 60-second clock skew tolerance
  const now = Math.floor(Date.now() / 1000);
  const CLOCK_SKEW_SECONDS = 60;

  // Check not-before (nbf) with skew tolerance
  if (payload.nbf && payload.nbf > now + CLOCK_SKEW_SECONDS) {
    throw new Error("Token not yet valid");
  }

  // Check expiration with skew tolerance
  if (payload.exp < now - CLOCK_SKEW_SECONDS) {
    throw new Error("Token expired");
  }

  // Validate audience (configurable via env, defaults to service name)
  const expectedAudience = env.EXPECTED_AUDIENCE || "gpg-signing-service";
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!audiences.includes(expectedAudience)) {
    throw new Error("Invalid token audience");
  }

  // Fetch JWKS and verify signature. If the cached JWKS doesn't have the
  // required key id, getJWKS will refresh from the network.
  const jwks = await getJWKS(payload.iss, env, header.kid);

  // Pre-flight: make sure a matching key exists and is intended for signatures.
  const matchingKey = jwks.keys.find((key) => key.kid === header.kid);
  // If we can positively identify the key in the JWKS and it declares a
  // non-signature use, reject early with a clear message. If no matching key
  // is found here, defer to jose's key selection which will yield a precise
  // error that we map below.
  if (matchingKey?.use && matchingKey.use !== "sig") {
    throw new Error("Key not intended for signatures");
  }

  // The `jose.jwtVerify` function handles finding the correct key from the JWKS
  // based on the `kid` in the token header, so manual key lookup is not needed.
  const JWKS = createLocalJWKSet(jwks);

  let verifiedPayload: JWTPayload;
  try {
    ({ payload: verifiedPayload } = await jwtVerify(token, JWKS, {
      issuer: allowedIssuers,
      algorithms: ALLOWED_ALGORITHMS,
      clockTolerance: "60s", // Allow for 60 seconds of clock skew
    }));
  } catch (e) {
    mapJoseError(e as Error & { code?: string });
  }

  return verifiedPayload as OIDCClaims;
}

// Exported for targeted testing of error mapping logic
export function mapJoseError(err: Error & { code?: string }): never {
  // Map jose error codes/messages to user-friendly, test-specific messages.
  if (err.code === "ERR_JWKS_NO_MATCHING_KEY") {
    throw new Error("Key not found");
  }
  if (err.message?.includes("signature verification failed")) {
    throw new Error("Invalid token signature");
  }
  throw err;
}

async function getJWKS(
  issuer: string,
  env: Env,
  expectedKid?: string,
): Promise<LegacyJWKSResponse> {
  const cacheKey = `jwks:${issuer}`;

  // Check cache first
  const cached = await env.JWKS_CACHE.get(cacheKey, "json");
  if (cached) {
    const cachedJWKS = cached as LegacyJWKSResponse;
    // If an expected kid is provided and it's not in the cached JWKS, refresh
    // from the origin to pick up key rotations.
    if (
      expectedKid
      && !cachedJWKS.keys?.some((k: { kid?: string }) => k.kid === expectedKid)
    ) {
      // fall through to network fetch below
    } else {
      return cachedJWKS;
    }
  }

  // Fetch JWKS from issuer with timeout
  const wellKnownUrl = `${issuer}/.well-known/openid-configuration`;
  const configResponse = await fetchWithTimeout(wellKnownUrl, {}, 10000);

  if (!configResponse.ok) {
    throw new Error(`Failed to fetch OIDC config from ${wellKnownUrl}`);
  }

  const config = (await configResponse.json()) as { jwks_uri: string };
  const jwksResponse = await fetchWithTimeout(config.jwks_uri, {}, 10000);

  if (!jwksResponse.ok) {
    throw new Error(`Failed to fetch JWKS from ${config.jwks_uri}`);
  }

  const jwks = (await jwksResponse.json()) as LegacyJWKSResponse;

  // Cache for 5 minutes (non-critical, don't fail on cache errors)
  try {
    await env.JWKS_CACHE.put(cacheKey, JSON.stringify(jwks), {
      expirationTtl: CACHE_TTL.JWKS / TIME.SECOND,
    });
  } catch (error) {
    logger.warn("Failed to cache JWKS", {
      error: error instanceof Error ? error.message : String(error),
      issuer,
    });
    // Continue - caching is optimization, not critical path
  }

  return jwks;
}
