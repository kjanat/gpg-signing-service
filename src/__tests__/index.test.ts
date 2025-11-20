// These imports are provided by @cloudflare/vitest-pool-workers
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck - cloudflare:test types are provided at runtime by vitest-pool-workers
import {
  createExecutionContext,
  env,
  waitOnExecutionContext,
} from "cloudflare:test";
import { describe, expect, it } from "vitest";
import app from "~/index";

describe("Global Error Handling", () => {
  it("should handle errors in publicKeyRoute", async () => {
    const ctx = createExecutionContext();

    // 1. Store a key with INVALID content to cause openpgp.readPrivateKey to throw
    const keyStorageId = env.KEY_STORAGE.idFromName("global");
    const keyStorage = env.KEY_STORAGE.get(keyStorageId);
    await keyStorage.fetch(
      new Request("http://internal/store-key", {
        method: "POST",
        body: JSON.stringify({
          armoredPrivateKey: "invalid-key-content",
          keyId: "error-test-key",
          fingerprint: "dummy-fingerprint",
          createdAt: new Date().toISOString(),
          algorithm: "RSA",
        }),
        headers: { "Content-Type": "application/json" },
      }),
    );

    const response = await app.fetch(
      new Request("http://localhost/public-key?keyId=error-test-key"),
      env,
      ctx,
    );
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(500);
    const body = (await response.json()) as { code: string };
    expect(body.code).toBe("KEY_PROCESSING_ERROR");
  });
});
