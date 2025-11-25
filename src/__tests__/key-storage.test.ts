import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const parseJson = async <T>(response: Response): Promise<T> =>
  (await response.json()) as T;

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
    const body = await parseJson<{ error: string }>(response);
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
    const body = await parseJson<{ error: string }>(response);
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
    const body = await parseJson<{ error: string }>(response);
    expect(body.error).toBeTruthy();
  });

  it("should use default keyId when not provided in /get-key", async () => {
    const id = env.KEY_STORAGE.idFromName("test-default-key");
    const stub = env.KEY_STORAGE.get(id);

    // First ensure the default key doesn't exist (or does, doesn't matter for coverage of the line)
    // We just want to hit the line `url.searchParams.get("keyId") || "default"`
    const response = await stub.fetch(new Request("http://internal/get-key"));

    // It should try to fetch "default" key and likely return 404 if not found
    expect(response.status).toBe(404);
    const body = await parseJson<{ error: string }>(response);
    expect(body.error).toBe("Key not found");
  });

  it("should catch unexpected errors in fetch", async () => {
    const id = env.KEY_STORAGE.idFromName("test-unexpected-error");
    const stub = env.KEY_STORAGE.get(id);

    // Test error handling by providing malformed JSON which triggers request.json() parse error
    const response = await stub.fetch(
      new Request("http://internal/store-key", {
        method: "POST",
        body: "invalid-json",
      }),
    );

    expect(response.status).toBe(500);
    const body = await parseJson<{ error: string }>(response);
    expect(body.error).toContain("Unexpected token"); // JSON parse error message
  });
});
