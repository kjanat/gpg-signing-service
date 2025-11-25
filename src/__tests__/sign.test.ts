import {
  createExecutionContext,
  env,
  waitOnExecutionContext,
} from "cloudflare:test";
import app from "gpg-signing-service";
import * as jose from "jose";
import * as openpgp from "openpgp";
import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import { logger } from "~/utils/logger";

const parseJson = async <T>(response: Response): Promise<T> =>
  (await response.json()) as T;

// Mock fetch for JWKS
const { signFetchMock } = vi.hoisted(() => ({ signFetchMock: vi.fn() }));

vi.mock("~/utils/fetch", () => ({ fetchWithTimeout: signFetchMock }));

// Mock audit logging to avoid D1 dependency in tests
vi.mock("~/utils/audit", async (importOriginal) => {
  const actual = await importOriginal<typeof import("~/utils/audit")>();
  return { ...actual, logAuditEvent: vi.fn(async () => undefined) };
});

// Helper to make requests
async function makeRequest(
  path: string,
  options: RequestInit = {},
): Promise<Response> {
  const ctx = createExecutionContext();
  const response = await app.fetch(
    new Request(`http://localhost${path}`, options),
    env,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return response;
}

// Helper to upload a test key
async function uploadTestKey(keyId: string) {
  const { privateKey } = await openpgp.generateKey({
    type: "ecc",
    curve: "ed25519Legacy",
    userIDs: [{ name: "Sign Test", email: "sign@test.com" }],
    passphrase: env.KEY_PASSPHRASE,
    format: "armored",
  });

  const ctx = createExecutionContext();
  await app.fetch(
    new Request("http://localhost/admin/keys", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.ADMIN_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ armoredPrivateKey: privateKey, keyId }),
    }),
    env,
    ctx,
  );
  await waitOnExecutionContext(ctx);
  return privateKey;
}

describe("Sign Route", () => {
  let oidcPrivateKey: CryptoKey;
  let oidcPublicKey: CryptoKey;
  const issuer = "https://token.actions.githubusercontent.com";
  const kid = "test-key";

  beforeAll(async () => {
    // Generate OIDC keys
    const keys = await jose.generateKeyPair("ES256");
    oidcPrivateKey = keys.privateKey;
    oidcPublicKey = keys.publicKey;
  });

  beforeEach(() => {
    vi.resetAllMocks();
    // Mock cache to return null by default (cache miss)
    vi.spyOn(env.JWKS_CACHE, "get").mockResolvedValue(
      null as unknown as Map<string, unknown>,
    );
    // Set allowed origins to ensure consistent behavior
    env.ALLOWED_ORIGINS = "https://allowed.com";
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  async function setupJWKSMock() {
    const jwk = await jose.exportJWK(oidcPublicKey);
    jwk.kid = kid;
    jwk.use = "sig";

    signFetchMock.mockImplementation(async (url: string) => {
      if (url === `${issuer}/.well-known/openid-configuration`) {
        return new Response(JSON.stringify({ jwks_uri: `${issuer}/jwks` }));
      }
      if (url === `${issuer}/jwks`) {
        return new Response(JSON.stringify({ keys: [jwk] }));
      }
      return new Response("Not Found", { status: 404 });
    });
  }

  async function createToken(claims: object = {}) {
    return new jose.SignJWT({
      iss: issuer,
      sub: "repo:user/repo:ref:refs/heads/main",
      aud: "gpg-signing-service",
      ...claims,
    })
      .setProtectedHeader({ alg: "ES256", kid })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(oidcPrivateKey);
  }

  describe("POST /sign", () => {
    it("should sign valid commit data", async () => {
      await setupJWKSMock();
      await uploadTestKey("A1B2C3D4E5F67890");
      const token = await createToken();

      const commitData =
        "tree 29ff16c9c14e2652b22f8b78bb08a5a07930c147\nparent ...";

      const response = await makeRequest("/sign?keyId=A1B2C3D4E5F67890", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: commitData,
      });

      expect(response.status).toBe(200);
      const signature = await response.text();
      expect(signature).toContain("-----BEGIN PGP SIGNATURE-----");
    });

    it("should return 400 if commit data is missing", async () => {
      await setupJWKSMock();
      const token = await createToken();

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "",
      });

      expect(response.status).toBe(400);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("INVALID_REQUEST");
    });

    it("should return 404 if key not found", async () => {
      await setupJWKSMock();
      const token = await createToken();
      const response = await makeRequest("/sign?keyId=FFFFFFFFFFFFFFFF", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      expect(response.status).toBe(404);
      // So it actually returns 500 for key not found in the current implementation!
      // Wait, let's check sign.ts again.

      // sign.ts:200
      // if (!keyResponse.ok) { throw new Error(...) }
      // catch (error) { return c.json(..., 500) }

      // So "Key not found" becomes a 500. This might be a bug or intended.
      // Based on the code I read, it returns 500.

      expect(response.status).toBe(404);
      const body = (await response.json()) as { error: string; code: string };
      expect(body.code).toBe("KEY_NOT_FOUND");
      expect(body.error).toContain("Key not found");
    });

    it("should use default key ID if not provided", async () => {
      await setupJWKSMock();
      await uploadTestKey(env.KEY_ID); // Upload default key
      const token = await createToken();

      const response = await makeRequest("/sign", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        body: "commit data",
      });

      expect(response.status).toBe(200);
      const signature = await response.text();
      expect(signature).toContain("-----BEGIN PGP SIGNATURE-----");
    });

    it("should return 503 when rate limiter fails", async () => {
      await setupJWKSMock();
      const token = await createToken();

      // Mock rate limiter to fail
      const originalIdFromName = env.RATE_LIMITER.idFromName;
      env.RATE_LIMITER.idFromName = () => {
        throw new Error("Rate limiter unavailable");
      };

      try {
        const response = await makeRequest("/sign", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: "commit data",
        });

        expect(response.status).toBe(503);
        const body = await parseJson<{ code: string }>(response);
        expect(body.code).toBe("RATE_LIMIT_ERROR");
      } finally {
        env.RATE_LIMITER.idFromName = originalIdFromName;
      }
    });

    it("should return 503 when rate limiter returns non-OK", async () => {
      await setupJWKSMock();
      const token = await createToken();

      // Mock rate limiter fetch to return 500
      const originalGet = env.RATE_LIMITER.get;
      env.RATE_LIMITER.get = () =>
        ({
          fetch: async () => new Response("Internal Error", { status: 500 }),
        }) as unknown as DurableObjectStub;

      try {
        const response = await makeRequest("/sign", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: "commit data",
        });

        expect(response.status).toBe(503);
        const body = await parseJson<{ code: string }>(response);
        expect(body.code).toBe("RATE_LIMIT_ERROR");
      } finally {
        env.RATE_LIMITER.get = originalGet;
      }
    });

    it("should return 429 when rate limit exceeded", async () => {
      await setupJWKSMock();
      const token = await createToken();

      // Mock rate limiter to return not allowed
      const originalGet = env.RATE_LIMITER.get;
      env.RATE_LIMITER.get = () =>
        ({
          fetch: async () =>
            new Response(
              JSON.stringify({
                allowed: false,
                remaining: 0,
                resetAt: Date.now() + 60000,
              }),
            ),
        }) as unknown as DurableObjectStub;

      try {
        const response = await makeRequest("/sign", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: "commit data",
        });

        expect(response.status).toBe(429);
        const body = await parseJson<{ code: string }>(response);
        expect(body.code).toBe("RATE_LIMITED");
      } finally {
        env.RATE_LIMITER.get = originalGet;
      }
    });

    it("should return 500 when signing fails with generic error", async () => {
      await setupJWKSMock();
      await uploadTestKey("5555555555555555");
      const token = await createToken();

      // Mock signCommitData to throw
      // We need to mock the module, but it's imported in the route.
      // Since we can't easily mock the utility function here without affecting other tests or requiring top-level mock,
      // we can simulate a failure by mocking the key storage to return a key that causes signing to fail?
      // Or we can mock `signCommitData` using `vi.mock` at the top of the file.
      // But `signCommitData` is not mocked at the top.

      // Alternative: Mock KEY_STORAGE to return a valid key, but then `signCommitData` fails.
      // If we pass an invalid key format, `openpgp.readPrivateKey` might throw "Key not found" or something else?
      // Let's try to mock `signCommitData` by adding it to the top-level mock if possible.
      // But changing top-level mocks requires refactoring.

      // Let's try to trigger an error in `signCommitData` by providing a key that is valid structure but fails signing?
      // Or just mock `env.KEY_STORAGE` to return a corrupted key that `signCommitData` (which calls `openpgp`) will fail on.
      // `signCommitData` calls `openpgp.readPrivateKey`.
      // If we return a key that `readPrivateKey` fails on, it might throw.

      const originalGet = env.KEY_STORAGE.get;
      env.KEY_STORAGE.get = () =>
        ({
          fetch: async () =>
            new Response(
              JSON.stringify({ armoredPrivateKey: "invalid-key-data" }),
            ),
        }) as unknown as DurableObjectStub;

      try {
        const response = await makeRequest("/sign?keyId=generic-error-key", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: "commit data",
        });

        expect(response.status).toBe(500);
        const body = await parseJson<{ code: string }>(response);
        expect(body.code).toBe("SIGN_ERROR");
      } finally {
        env.KEY_STORAGE.get = originalGet;
      }
    });

    it("should handle non-Error exceptions", async () => {
      await setupJWKSMock();
      const token = await createToken();

      // Mock KEY_STORAGE to throw a string
      const originalGet = env.KEY_STORAGE.get;
      const mockFetch = vi.fn().mockRejectedValue("String error");
      env.KEY_STORAGE.get = () =>
        ({ fetch: mockFetch }) as unknown as DurableObjectStub;

      try {
        const response = await makeRequest("/sign?keyId=8888888888888888", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: "commit data",
        });

        expect(response.status).toBe(500);
        const body = await parseJson<{ error: string }>(response);
        expect(body.error).toBe("Signing failed");
      } finally {
        env.KEY_STORAGE.get = originalGet;
      }
    });
    it("should propagate explicit upstream error", async () => {
      await setupJWKSMock();
      const token = await createToken();

      // Mock KEY_STORAGE to return 500 with explicit error
      const originalGet = env.KEY_STORAGE.get;
      env.KEY_STORAGE.get = () =>
        ({
          fetch: async () =>
            new Response(JSON.stringify({ error: "Upstream failure" }), {
              status: 500,
            }),
        }) as unknown as DurableObjectStub;

      try {
        const response = await makeRequest("/sign?keyId=9999999999999999", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: "commit data",
        });

        expect(response.status).toBe(500);
        const body = await parseJson<{ error: string }>(response);
        expect(body.error).toBe("Upstream failure");
      } finally {
        env.KEY_STORAGE.get = originalGet;
      }
    });
  });

  describe("Audit Logging Catch Handlers", () => {
    it("should log audit failures via catch handler on sign success", async () => {
      await setupJWKSMock();
      const token = await createToken();

      // Spy on console.error to verify catch handler executes
      const loggerSpy = vi.spyOn(logger, "error").mockImplementation(() => {});
      const { logAuditEvent } = await import("~/utils/audit");

      // Upload a key first
      const keyId = "SIGNCATCH1234567";
      await uploadTestKey(keyId);

      // Mock to reject once to trigger catch
      vi.mocked(logAuditEvent).mockRejectedValueOnce(
        new Error("Audit DB connection failed"),
      );

      const ctx = createExecutionContext();
      await app.fetch(
        new Request(`http://localhost/sign?keyId=${keyId}`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: "commit data for audit catch test",
        }),
        env,
        ctx,
      );

      // Wait for background tasks
      await waitOnExecutionContext(ctx);

      // Verify catch handler logged the error
      expect(loggerSpy).toHaveBeenCalledWith(
        "Background task failed",
        expect.objectContaining({
          requestId: expect.any(String),
          error: expect.any(String),
        }),
      );

      loggerSpy.mockRestore();
    });

    it("should log audit failures via catch handler on sign error", async () => {
      await setupJWKSMock();
      const token = await createToken();
      const loggerSpy = vi.spyOn(logger, "error").mockImplementation(() => {});
      const { logAuditEvent } = await import("~/utils/audit");

      // Mock to reject for error audit
      vi.mocked(logAuditEvent).mockRejectedValueOnce(
        new Error("Audit DB unavailable"),
      );

      const ctx = createExecutionContext();
      await app.fetch(
        new Request("http://localhost/sign?keyId=NONEXISTENT123", {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` },
          body: "commit data",
        }),
        env,
        ctx,
      );

      await waitOnExecutionContext(ctx);

      expect(loggerSpy).toHaveBeenCalledWith(
        "Background task failed",
        expect.objectContaining({
          requestId: expect.any(String),
          error: expect.any(String),
        }),
      );

      loggerSpy.mockRestore();
    });
  });
});
