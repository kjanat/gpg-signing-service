// These imports are provided by @cloudflare/vitest-pool-workers
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck - cloudflare:test types are provided at runtime by vitest-pool-workers
import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

describe("KeyStorage Durable Object", () => {
  it("should return 404 for unknown path", async () => {
    const id = env.KEY_STORAGE.idFromName("test-unknown-path");
    const stub = env.KEY_STORAGE.get(id);
    const response = await stub.fetch(new Request("http://internal/unknown"));
    expect(response.status).toBe(404);
  });

  it("should return 405 for invalid method on /store-key", async () => {
    const id = env.KEY_STORAGE.idFromName("test-method-store");
    const stub = env.KEY_STORAGE.get(id);
    const response = await stub.fetch(
      new Request("http://internal/store-key", { method: "GET" }),
    );
    expect(response.status).toBe(405);
  });

  it("should return 400 for missing fields on /store-key", async () => {
    const id = env.KEY_STORAGE.idFromName("test-missing-fields");
    const stub = env.KEY_STORAGE.get(id);
    const response = await stub.fetch(
      new Request("http://internal/store-key", {
        method: "POST",
        body: JSON.stringify({}),
      }),
    );
    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.error).toBe("Missing required fields");
  });

  it("should return 405 for invalid method on /delete-key", async () => {
    const id = env.KEY_STORAGE.idFromName("test-method-delete");
    const stub = env.KEY_STORAGE.get(id);
    const response = await stub.fetch(
      new Request("http://internal/delete-key", { method: "POST" }),
    );
    expect(response.status).toBe(405);
  });

  it("should return 400 for missing keyId on /delete-key", async () => {
    const id = env.KEY_STORAGE.idFromName("test-missing-keyid");
    const stub = env.KEY_STORAGE.get(id);
    const response = await stub.fetch(
      new Request("http://internal/delete-key", { method: "DELETE" }),
    );
    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.error).toBe("Key ID required");
  });

  it("should handle internal errors", async () => {
    const id = env.KEY_STORAGE.idFromName("test-internal-error");
    const stub = env.KEY_STORAGE.get(id);

    // We can't easily mock the internal state storage failure from here without
    // more complex mocking, but we can trigger an error by passing invalid JSON
    // to an endpoint that expects it, if the error handling catches it.
    // However, the DO implementation wraps everything in try/catch.
    // Let's try to trigger an error in `storeKey` by passing invalid JSON
    // which will cause `request.json()` to fail inside the try block.

    const response = await stub.fetch(
      new Request("http://internal/store-key", {
        method: "POST",
        body: "invalid-json",
      }),
    );

    expect(response.status).toBe(500);
    const body = await response.json();
    expect(body.error).toBeTruthy();
  });
});
