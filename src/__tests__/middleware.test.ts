import {
  createExecutionContext,
  env,
  waitOnExecutionContext,
} from "cloudflare:test";
import app from "gpg-signing-service";
import * as jose from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const parseJson = async <T>(response: Response): Promise<T> =>
  (await response.json()) as T;

// Mock fetch for JWKS
const { middlewareFetchMock } = vi.hoisted(() => ({
  middlewareFetchMock: vi.fn(),
}));

vi.mock("~/utils/fetch", () => ({
  fetchWithTimeout: middlewareFetchMock,
}));

// Mock audit logging to avoid database errors in tests
vi.mock("~/utils/audit", async (importOriginal) => {
  const actual = await importOriginal<typeof import("~/utils/audit")>();
  return {
    ...actual,
    logAuditEvent: vi.fn(async () => undefined),
  };
});

// Helper to make requests
async function makeRequest(
  path: string,
  options: RequestInit = {},
  customEnv?: Partial<Env>,
): Promise<Response> {
  const ctx = createExecutionContext();
  const request = new Request(`http://localhost${path}`, options);
  const response = await app.fetch(
    request,
    customEnv ? { ...env, ...customEnv } : env,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return response;
}

describe("Security Headers Middleware", () => {
  it("should set X-Content-Type-Options", async () => {
    const response = await makeRequest("/health");
    expect(response.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });

  it("should set X-Frame-Options", async () => {
    const response = await makeRequest("/health");
    expect(response.headers.get("X-Frame-Options")).toBe("DENY");
  });

  it("should set HSTS header", async () => {
    const response = await makeRequest("/health");
    expect(response.headers.get("Strict-Transport-Security")).toBe(
      "max-age=31536000; includeSubDomains; preload",
    );
  });

  it("should set Referrer-Policy", async () => {
    const response = await makeRequest("/health");
    expect(response.headers.get("Referrer-Policy")).toBe(
      "strict-origin-when-cross-origin",
    );
  });

  it("should set Content-Security-Policy", async () => {
    const response = await makeRequest("/health");
    expect(response.headers.get("Content-Security-Policy")).toBe(
      "default-src 'none'; frame-ancestors 'none'",
    );
  });

  it("should set Permissions-Policy", async () => {
    const response = await makeRequest("/health");
    expect(response.headers.get("Permissions-Policy")).toBe(
      "geolocation=(), microphone=(), camera=()",
    );
  });

  it("should handle CORS preflight", async () => {
    const response = await makeRequest("/health", {
      method: "OPTIONS",
      headers: {
        Origin: "https://allowed-origin.com",
        "Access-Control-Request-Method": "GET",
      },
    });
    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe(
      "https://allowed-origin.com",
    );
  });

  it("should handle CORS actual request", async () => {
    const response = await makeRequest("/health", {
      headers: {
        Origin: "https://allowed-origin.com",
      },
    });
    expect(response.headers.get("Access-Control-Allow-Origin")).toBe(
      "https://allowed-origin.com",
    );
  });

  it("should handle CORS OPTIONS with disallowed origin", async () => {
    // Set allowed origins to ensure strict checking
    env.ALLOWED_ORIGINS = "https://allowed.com";

    const response = await makeRequest("/health", {
      method: "OPTIONS",
      headers: {
        Origin: "https://disallowed-origin.com",
      },
    });
    expect(response.status).toBe(204);
    expect(response.headers.get("Access-Control-Allow-Origin")).toBeNull();
  });

  describe("OIDC Token Validation", () => {
    beforeEach(() => {
      vi.resetAllMocks();
      // Mock cache to return null by default (cache miss)
      vi.spyOn(env.JWKS_CACHE, "get").mockResolvedValue(null as any);
    });

    afterEach(() => {
      vi.resetAllMocks();
    });

    async function setupJWKSMock(
      issuer: string,
      kid: string,
      publicKey: CryptoKey,
    ) {
      const jwk = await jose.exportJWK(publicKey);
      jwk.kid = kid;
      jwk.use = "sig";

      // Mock OIDC discovery
      middlewareFetchMock.mockImplementation(async (url: string) => {
        if (url === `${issuer}/.well-known/openid-configuration`) {
          return new Response(JSON.stringify({ jwks_uri: `${issuer}/jwks` }));
        }
        if (url === `${issuer}/jwks`) {
          return new Response(JSON.stringify({ keys: [jwk] }));
        }
        return new Response("Not Found", { status: 404 });
      });
    }

    it("should reject key not intended for signatures", async () => {
      const { publicKey } = await jose.generateKeyPair("ES256");
      const issuer = "https://token.actions.githubusercontent.com";
      const kid = "enc-key";

      // Setup mock with use: "enc"
      const jwk = await jose.exportJWK(publicKey);
      jwk.kid = kid;
      jwk.use = "enc";

      middlewareFetchMock.mockImplementation(async (url: string) => {
        if (url === `${issuer}/.well-known/openid-configuration`) {
          return new Response(JSON.stringify({ jwks_uri: `${issuer}/jwks` }));
        }
        if (url === `${issuer}/jwks`) {
          return new Response(JSON.stringify({ keys: [jwk] }));
        }
        return new Response("Not Found", { status: 404 });
      });

      const { privateKey } = await jose.generateKeyPair("ES256");
      const token = await new jose.SignJWT({
        iss: issuer,
        sub: "test",
        aud: "gpg-signing-service",
      })
        .setProtectedHeader({ alg: "ES256", kid })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(privateKey);

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain("Key not intended for signatures");
    });

    it("should handle OIDC config fetch failure", async () => {
      middlewareFetchMock.mockResolvedValue(
        new Response("Error", { status: 500 }),
      );

      const { privateKey } = await jose.generateKeyPair("ES256");
      const token = await new jose.SignJWT({
        iss: "https://token.actions.githubusercontent.com",
        sub: "test",
        aud: "gpg-signing-service",
      })
        .setProtectedHeader({ alg: "ES256", kid: "test" })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(privateKey);

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain("Failed to fetch OIDC config");
    });

    it("should handle JWKS fetch failure", async () => {
      const issuer = "https://token.actions.githubusercontent.com";
      middlewareFetchMock.mockImplementation(async (url: string) => {
        if (url === `${issuer}/.well-known/openid-configuration`) {
          return new Response(JSON.stringify({ jwks_uri: `${issuer}/jwks` }));
        }
        return new Response("Error", { status: 500 });
      });

      const { privateKey } = await jose.generateKeyPair("ES256");
      const token = await new jose.SignJWT({
        iss: issuer,
        sub: "test",
        aud: "gpg-signing-service",
      })
        .setProtectedHeader({ alg: "ES256", kid: "test" })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(privateKey);

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain("Failed to fetch JWKS");
    });

    it("should handle cache put failure", async () => {
      const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
      const issuer = "https://token.actions.githubusercontent.com";
      const kid = "test-key";

      await setupJWKSMock(issuer, kid, publicKey);

      // Mock cache put to fail
      vi.spyOn(env.JWKS_CACHE, "put").mockRejectedValue(
        new Error("Cache error"),
      );

      const token = await new jose.SignJWT({
        iss: issuer,
        sub: "test",
        aud: "gpg-signing-service",
      })
        .setProtectedHeader({ alg: "ES256", kid })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(privateKey);

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      // Should still succeed despite cache error
      expect(response.status).not.toBe(401);
    });

    it("should reject missing authorization header", async () => {
      const response = await makeRequest("/sign", {
        method: "POST",
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("AUTH_MISSING");
    });

    it("should reject non-Bearer authorization", async () => {
      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: "Basic dXNlcjpwYXNz" },
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("AUTH_MISSING");
    });

    it("should reject token with wrong number of parts", async () => {
      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: "Bearer only.two" },
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: string; code: string };
      expect(body.code).toBe("AUTH_INVALID");
      expect(body.error).toContain("Invalid token format");
    });

    it("should reject token with invalid base64 encoding", async () => {
      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: "Bearer !!!.!!!.!!!" },
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: string; code: string };
      expect(body.code).toBe("AUTH_INVALID");
    });

    it("should validate a correct token", async () => {
      const { publicKey, privateKey } = await jose.generateKeyPair("ES256");
      const issuer =
        "https://token.actions.githubusercontent.com/unique-test-issuer";
      const kid = "test-key";

      await setupJWKSMock(issuer, kid, publicKey);

      const token = await new jose.SignJWT({
        iss: issuer,
        sub: "repo:user/repo:ref:refs/heads/main",
        aud: "gpg-signing-service",
      })
        .setProtectedHeader({ alg: "ES256", kid })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(privateKey);

      // We expect 400 because the token is valid but the body is empty/invalid for the endpoint
      // This proves authentication passed
      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      expect(response.status).not.toBe(401);
    });

    it("should reject token signed by unknown key", async () => {
      const { privateKey } = await jose.generateKeyPair("ES256");
      const issuer = "https://token.actions.githubusercontent.com";

      // Setup mock with DIFFERENT key
      const { publicKey: otherKey } = await jose.generateKeyPair("ES256");
      await setupJWKSMock(issuer, "other-key", otherKey);

      const token = await new jose.SignJWT({
        iss: issuer,
        sub: "test",
        aud: "gpg-signing-service",
      })
        .setProtectedHeader({ alg: "ES256", kid: "unknown-key" })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(privateKey);

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain("Key not found");
    });

    it("should reject token with invalid signature", async () => {
      const { publicKey } = await jose.generateKeyPair("ES256");
      const { privateKey: otherKey } = await jose.generateKeyPair("ES256");
      const issuer = "https://token.actions.githubusercontent.com";
      const kid = "test-key";

      await setupJWKSMock(issuer, kid, publicKey);

      // Sign with WRONG private key but claim it's the correct kid
      const token = await new jose.SignJWT({
        iss: issuer,
        sub: "test",
        aud: "gpg-signing-service",
      })
        .setProtectedHeader({ alg: "ES256", kid })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(otherKey);

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain("Invalid token signature");
    });

    it("should reject token with disallowed algorithm", async () => {
      // Generate RS256 key (allowed) but we'll try to use HS256 (disallowed)
      // Note: jose won't let us sign HS256 with RSA key easily, so we just mock the token structure
      // or use a separate HS256 key
      const secret = new TextEncoder().encode("secret");
      const token = await new jose.SignJWT({
        iss: "https://token.actions.githubusercontent.com",
        sub: "test",
        aud: "gpg-signing-service",
      })
        .setProtectedHeader({ alg: "HS256", kid: "test" })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(secret);

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain("Algorithm not allowed");
    });

    it("should reject token from disallowed issuer", async () => {
      const { privateKey } = await jose.generateKeyPair("ES256");
      const token = await new jose.SignJWT({
        iss: "https://malicious-issuer.com",
        sub: "test",
        aud: "gpg-signing-service",
      })
        .setProtectedHeader({ alg: "ES256", kid: "test" })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(privateKey);

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain("Issuer not allowed");
    });

    it("should reject expired token", async () => {
      const { privateKey } = await jose.generateKeyPair("ES256");
      const token = await new jose.SignJWT({
        iss: "https://token.actions.githubusercontent.com",
        sub: "test",
        aud: "gpg-signing-service",
      })
        .setProtectedHeader({ alg: "ES256", kid: "test" })
        .setIssuedAt()
        .setExpirationTime("-1h") // Expired
        .sign(privateKey);

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain("Token expired");
    });

    it("should reject token not yet valid (nbf)", async () => {
      const { privateKey } = await jose.generateKeyPair("ES256");
      const token = await new jose.SignJWT({
        iss: "https://token.actions.githubusercontent.com",
        sub: "test",
        aud: "gpg-signing-service",
      })
        .setProtectedHeader({ alg: "ES256", kid: "test" })
        .setIssuedAt()
        .setNotBefore("1h") // Not valid yet
        .setExpirationTime("2h")
        .sign(privateKey);

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: string };
      expect(body.error).toContain("Token not yet valid");
    });

    async function createToken(
      claims: object = {},
      keyPair?: any,
      alg: string = "ES256",
      kid: string = "test-key",
    ) {
      if (!keyPair) {
        keyPair = await jose.generateKeyPair(alg);
      }
      return new jose.SignJWT({
        iss: "https://token.actions.githubusercontent.com",
        sub: "repo:user/repo:ref:refs/heads/main",
        aud: "gpg-signing-service",
        ...claims,
      })
        .setProtectedHeader({ alg, kid })
        .setIssuedAt()
        .setExpirationTime("1h")
        .sign(keyPair.privateKey);
    }

    it("should use cached JWKS", async () => {
      const keyPair = await jose.generateKeyPair("RS256");
      const token = await createToken({}, keyPair, "RS256", "test-key-RS256");
      const jwk = await jose.exportJWK(keyPair.publicKey);
      jwk.kid = "test-key-RS256";
      jwk.use = "sig";

      // Mock cache
      const mockCache = {
        get: vi.fn().mockResolvedValue({ keys: [jwk] }),
        put: vi.fn(),
        delete: vi.fn(),
        list: vi.fn(),
      };

      const response = await makeRequest(
        "/sign",
        {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: "commit data",
        },
        { JWKS_CACHE: mockCache as any },
      );

      // 404 means OIDC passed (using cached key) and it reached the route
      expect(response.status).toBe(404);
    });

    it("should reject token with wrong audience", async () => {
      const token = await createToken({ aud: "wrong-audience" });
      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });
      expect(response.status).toBe(401);
      const body = await parseJson<{ error: string }>(response);
      expect(body.error).toBe("Invalid token audience");
    });

    it("should accept token with array audience containing correct audience", async () => {
      const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
      const issuer = "https://token.actions.githubusercontent.com";
      const kid = "test-key";

      await setupJWKSMock(issuer, kid, publicKey);

      const token = await createToken(
        { aud: ["other-service", "gpg-signing-service"] },
        { privateKey },
        "ES256",
        kid,
      );

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });
      // 404 means OIDC passed
      if (response.status === 401) {
        const body = await parseJson<unknown>(response);
        console.error("OIDC Array Audience Test Failed:", body);
      }
      expect(response.status).toBe(404);
    });

    it("should handle non-Error exceptions during validation", async () => {
      const { privateKey } = await jose.generateKeyPair("ES256");
      const token = await createToken({}, { privateKey });

      // Mock JWKS_CACHE to throw a string
      vi.spyOn(env.JWKS_CACHE, "get").mockRejectedValue("String error");

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      expect(response.status).toBe(401);
      const body = await parseJson<{ error: string }>(response);
      expect(body.error).toBe("Invalid token");
    });

    describe("Algorithm Support", () => {
      const algorithms = ["RS256", "RS384", "RS512", "ES384"];

      for (const alg of algorithms) {
        it(`should support ${alg} algorithm`, async () => {
          // Generate key pair for the algorithm
          const { privateKey, publicKey } = await jose.generateKeyPair(alg);
          const jwk = await jose.exportJWK(publicKey);
          jwk.kid = `test-key-${alg}`;
          jwk.use = "sig";

          // Mock JWKS response
          // Mock JWKS response
          middlewareFetchMock.mockImplementation(async (url) => {
            if (
              url
                === "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
            ) {
              return new Response(
                JSON.stringify({
                  jwks_uri: "https://token.actions.githubusercontent.com/jwks",
                }),
              );
            }
            if (url === "https://token.actions.githubusercontent.com/jwks") {
              return new Response(JSON.stringify({ keys: [jwk] }));
            }
            return new Response("Not Found", { status: 404 });
          });

          // Create token
          const token = await new jose.SignJWT({
            iss: "https://token.actions.githubusercontent.com",
            sub: "repo:user/repo:ref:refs/heads/main",
            aud: "gpg-signing-service",
          })
            .setProtectedHeader({ alg, kid: jwk.kid })
            .setIssuedAt()
            .setExpirationTime("1h")
            .sign(privateKey);

          const response = await makeRequest("/sign", {
            method: "POST",
            headers: { Authorization: `Bearer ${token}` },
            body: "commit data",
          });

          // 404 means OIDC passed and it reached the route (which failed to find key)
          expect(response.status).toBe(404);
        });
      }
    });
  });

  describe("Admin Auth Middleware", () => {
    it("should reject missing authorization header", async () => {
      const response = await makeRequest("/admin/keys");

      expect(response.status).toBe(401);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("AUTH_MISSING");
    });

    it("should reject non-Bearer authorization", async () => {
      const response = await makeRequest("/admin/keys", {
        headers: { Authorization: "Basic dXNlcjpwYXNz" },
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("AUTH_MISSING");
    });

    it("should reject invalid admin token", async () => {
      const response = await makeRequest("/admin/keys", {
        headers: { Authorization: "Bearer wrong-token" },
      });

      expect(response.status).toBe(401);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("AUTH_INVALID");
    });

    it("should accept valid admin token", async () => {
      const response = await makeRequest("/admin/keys", {
        headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
      });

      // Should not be 401
      expect(response.status).not.toBe(401);
    });

    it("should handle rate limiter failure", async () => {
      // Mock RATE_LIMITER failure
      const originalIdFromName = env.RATE_LIMITER.idFromName;
      env.RATE_LIMITER.idFromName = () => {
        throw new Error("Rate limiter failure");
      };

      try {
        const response = await makeRequest("/admin/keys", {
          headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
        });

        expect(response.status).toBe(503);
        const body = (await response.json()) as { code: string };
        expect(body.code).toBe("RATE_LIMIT_ERROR");
      } finally {
        env.RATE_LIMITER.idFromName = originalIdFromName;
      }
    });
  });
});
