import type { MiddlewareHandler } from 'hono';
import type { Env, Variables, OIDCClaims, JWKSResponse } from '../types';

// OIDC validation middleware
export const oidcAuth: MiddlewareHandler<{ Bindings: Env; Variables: Variables }> = async (c, next) => {
  const authHeader = c.req.header('Authorization');

  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'Missing authorization header', code: 'AUTH_MISSING' }, 401);
  }

  const token = authHeader.slice(7);

  try {
    const claims = await validateOIDCToken(token, c.env);

    // Store claims in context for downstream use
    c.set('oidcClaims', claims);
    c.set('identity', `${claims.iss}:${claims.sub}`);

    await next();
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Token validation failed';
    return c.json({ error: message, code: 'AUTH_INVALID' }, 401);
  }
};

// Admin token auth for management endpoints
export const adminAuth: MiddlewareHandler<{ Bindings: Env }> = async (c, next) => {
  const authHeader = c.req.header('Authorization');

  if (!authHeader?.startsWith('Bearer ')) {
    return c.json({ error: 'Missing authorization header', code: 'AUTH_MISSING' }, 401);
  }

  const token = authHeader.slice(7);

  if (token !== c.env.ADMIN_TOKEN) {
    return c.json({ error: 'Invalid admin token', code: 'AUTH_INVALID' }, 401);
  }

  await next();
};

async function validateOIDCToken(token: string, env: Env): Promise<OIDCClaims> {
  // Decode JWT header and payload (without verification first)
  const parts = token.split('.');
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) {
    throw new Error('Invalid token format');
  }

  const header = JSON.parse(atob(parts[0])) as { kid: string; alg: string };
  const payload = JSON.parse(atob(parts[1])) as OIDCClaims;

  // Validate issuer
  const allowedIssuers = env.ALLOWED_ISSUERS.split(',');
  if (!allowedIssuers.includes(payload.iss)) {
    throw new Error(`Issuer not allowed: ${payload.iss}`);
  }

  // Check expiration
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) {
    throw new Error('Token expired');
  }

  // Fetch JWKS and verify signature
  const jwks = await getJWKS(payload.iss, env);
  const key = jwks.keys.find((k: JWKSResponse['keys'][0]) => k.kid === header.kid);

  if (!key) {
    throw new Error('Key not found in JWKS');
  }

  // Import the public key
  const cryptoKey = await importJWK(key, header.alg);

  // Verify signature
  const signatureValid = await verifySignature(
    `${parts[0]}.${parts[1]}`,
    parts[2],
    cryptoKey,
    header.alg
  );

  if (!signatureValid) {
    throw new Error('Invalid token signature');
  }

  return payload;
}

async function getJWKS(issuer: string, env: Env): Promise<JWKSResponse> {
  const cacheKey = `jwks:${issuer}`;

  // Check cache first
  const cached = await env.JWKS_CACHE.get(cacheKey, 'json');
  if (cached) {
    return cached as JWKSResponse;
  }

  // Fetch JWKS from issuer
  const wellKnownUrl = `${issuer}/.well-known/openid-configuration`;
  const configResponse = await fetch(wellKnownUrl);

  if (!configResponse.ok) {
    throw new Error(`Failed to fetch OIDC config from ${wellKnownUrl}`);
  }

  const config = await configResponse.json() as { jwks_uri: string };
  const jwksResponse = await fetch(config.jwks_uri);

  if (!jwksResponse.ok) {
    throw new Error(`Failed to fetch JWKS from ${config.jwks_uri}`);
  }

  const jwks = await jwksResponse.json() as JWKSResponse;

  // Cache for 5 minutes
  await env.JWKS_CACHE.put(cacheKey, JSON.stringify(jwks), { expirationTtl: 300 });

  return jwks;
}

async function importJWK(jwk: JWKSResponse['keys'][0], alg: string): Promise<CryptoKey> {
  const algorithm = getAlgorithm(alg);

  return crypto.subtle.importKey(
    'jwk',
    jwk,
    algorithm,
    false,
    ['verify']
  );
}

function getAlgorithm(alg: string): { name: string; hash?: string; namedCurve?: string } {
  switch (alg) {
    case 'RS256':
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
    case 'RS384':
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' };
    case 'RS512':
      return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' };
    case 'ES256':
      return { name: 'ECDSA', namedCurve: 'P-256' };
    case 'ES384':
      return { name: 'ECDSA', namedCurve: 'P-384' };
    default:
      throw new Error(`Unsupported algorithm: ${alg}`);
  }
}

async function verifySignature(
  data: string,
  signature: string,
  key: CryptoKey,
  alg: string
): Promise<boolean> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);

  // Base64url decode signature
  const signatureBuffer = base64UrlDecode(signature);

  const algorithm = alg.startsWith('ES')
    ? { name: 'ECDSA', hash: `SHA-${alg.slice(2)}` }
    : { name: 'RSASSA-PKCS1-v1_5' };

  return crypto.subtle.verify(algorithm, key, signatureBuffer, dataBuffer);
}

function base64UrlDecode(input: string): ArrayBuffer {
  // Convert base64url to base64
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);

  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}
