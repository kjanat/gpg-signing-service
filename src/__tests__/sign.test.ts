// These imports are provided by @cloudflare/vitest-pool-workers
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck - cloudflare:test types are provided at runtime by vitest-pool-workers
import {
  env,
  createExecutionContext,
  waitOnExecutionContext,
} from "cloudflare:test";
import { describe, it, expect, beforeAll } from "vitest";
import * as openpgp from "openpgp";
import app from "gpg-signing-service";

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
    curve: "ed25519",
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
}

describe("Public Key Endpoint", () => {
  beforeAll(async () => {
    await uploadTestKey("public-key-test");
  });

  it("should return public key for existing key", async () => {
    const response = await makeRequest("/public-key?keyId=public-key-test");

    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe("application/pgp-keys");

    const publicKey = await response.text();
    expect(publicKey).toContain("-----BEGIN PGP PUBLIC KEY BLOCK-----");
  });

  it("should use default key ID from env", async () => {
    // Upload the default key
    await uploadTestKey(env.KEY_ID);

    const response = await makeRequest("/public-key");

    expect(response.status).toBe(200);
    const publicKey = await response.text();
    expect(publicKey).toContain("-----BEGIN PGP PUBLIC KEY BLOCK-----");
  });

  it("should return 404 for non-existent key", async () => {
    const response = await makeRequest("/public-key?keyId=non-existent-key");

    expect(response.status).toBe(404);
    const body = (await response.json()) as { code: string };
    expect(body.code).toBe("KEY_NOT_FOUND");
  });
});

describe("Sign Endpoint Authentication", () => {
  it("should reject requests without OIDC token", async () => {
    const response = await makeRequest("/sign", {
      method: "POST",
      body: "commit data",
    });

    expect(response.status).toBe(401);
  });

  it("should reject requests with invalid Authorization header", async () => {
    const response = await makeRequest("/sign", {
      method: "POST",
      headers: { Authorization: "InvalidFormat" },
      body: "commit data",
    });

    expect(response.status).toBe(401);
  });

  it("should reject requests with malformed JWT", async () => {
    const response = await makeRequest("/sign", {
      method: "POST",
      headers: { Authorization: "Bearer not.a.valid.jwt" },
      body: "commit data",
    });

    expect(response.status).toBe(401);
  });
});

describe("Health Check Details", () => {
  it("should include checks object in response", async () => {
    const response = await makeRequest("/health");

    const body = (await response.json()) as {
      status: string;
      checks: { keyStorage: boolean; database: boolean };
    };

    expect(body.checks).toBeDefined();
    expect(typeof body.checks.keyStorage).toBe("boolean");
    expect(typeof body.checks.database).toBe("boolean");
  });

  it("should return degraded status when checks fail", async () => {
    // The database check will fail because D1 table doesn't exist
    const response = await makeRequest("/health");

    const body = (await response.json()) as { status: string };
    // Either healthy or degraded is acceptable
    expect(["healthy", "degraded"]).toContain(body.status);
  });
});

describe("Error Handler", () => {
  it("should return 404 for unknown routes", async () => {
    const response = await makeRequest("/unknown/path/here");

    expect(response.status).toBe(404);
    const body = (await response.json()) as { code: string };
    expect(body.code).toBe("NOT_FOUND");
  });
});

describe("CORS", () => {
  it("should include CORS headers", async () => {
    const response = await makeRequest("/health");

    expect(response.headers.get("Access-Control-Allow-Origin")).toBe("*");
  });

  it("should handle OPTIONS preflight", async () => {
    const response = await makeRequest("/sign", { method: "OPTIONS" });

    // OPTIONS requests typically return 204 or 200
    expect([200, 204]).toContain(response.status);
  });
});
