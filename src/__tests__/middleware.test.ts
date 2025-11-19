// These imports are provided by @cloudflare/vitest-pool-workers
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck - cloudflare:test types are provided at runtime by vitest-pool-workers
import {
  env,
  createExecutionContext,
  waitOnExecutionContext,
} from "cloudflare:test";
import { describe, it, expect } from "vitest";
import app from "../index";

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

// Helper to create a fake JWT for testing validation
function createFakeJWT(
  header: object,
  payload: object,
  signature = "fakesig",
): string {
  const encHeader = btoa(JSON.stringify(header))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  const encPayload = btoa(JSON.stringify(payload))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
  return `${encHeader}.${encPayload}.${signature}`;
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

  it("should set X-XSS-Protection", async () => {
    const response = await makeRequest("/health");
    expect(response.headers.get("X-XSS-Protection")).toBe("1; mode=block");
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
});

describe("OIDC Token Validation", () => {
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

  it("should reject token with disallowed algorithm", async () => {
    const token = createFakeJWT(
      { alg: "HS256", kid: "test" },
      {
        iss: "https://token.actions.githubusercontent.com",
        sub: "test",
        exp: Math.floor(Date.now() / 1000) + 3600,
        aud: "gpg-signing-service",
      },
    );

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
    const token = createFakeJWT(
      { alg: "RS256", kid: "test" },
      {
        iss: "https://malicious-issuer.com",
        sub: "test",
        exp: Math.floor(Date.now() / 1000) + 3600,
        aud: "gpg-signing-service",
      },
    );

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
    const token = createFakeJWT(
      { alg: "RS256", kid: "test" },
      {
        iss: "https://token.actions.githubusercontent.com",
        sub: "test",
        exp: Math.floor(Date.now() / 1000) - 3600, // expired
        aud: "gpg-signing-service",
      },
    );

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
    const token = createFakeJWT(
      { alg: "RS256", kid: "test" },
      {
        iss: "https://token.actions.githubusercontent.com",
        sub: "test",
        exp: Math.floor(Date.now() / 1000) + 7200,
        nbf: Math.floor(Date.now() / 1000) + 3600, // not valid yet
        aud: "gpg-signing-service",
      },
    );

    const response = await makeRequest("/sign", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: "commit data",
    });

    expect(response.status).toBe(401);
    const body = (await response.json()) as { error: string };
    expect(body.error).toContain("Token not yet valid");
  });

  it("should reject token with wrong audience", async () => {
    const token = createFakeJWT(
      { alg: "RS256", kid: "test" },
      {
        iss: "https://token.actions.githubusercontent.com",
        sub: "test",
        exp: Math.floor(Date.now() / 1000) + 3600,
        aud: "wrong-audience",
      },
    );

    const response = await makeRequest("/sign", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: "commit data",
    });

    expect(response.status).toBe(401);
    const body = (await response.json()) as { error: string };
    expect(body.error).toContain("Invalid token audience");
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
});
