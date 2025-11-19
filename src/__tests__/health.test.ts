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

describe("Health Endpoint", () => {
  it("should respond to health check", async () => {
    const request = new Request("http://localhost/health");
    const ctx = createExecutionContext();
    const response = await app.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);

    expect([200, 503]).toContain(response.status);
    const body = (await response.json()) as {
      status: string;
      timestamp: string;
      version: string;
    };
    expect(body).toHaveProperty("status");
    expect(body).toHaveProperty("timestamp");
    expect(body).toHaveProperty("version");
    expect(["healthy", "degraded"]).toContain(body.status);
  });

  it("should return correct content type", async () => {
    const request = new Request("http://localhost/health");
    const ctx = createExecutionContext();
    const response = await app.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.headers.get("content-type")).toContain("application/json");
  });
});

describe("404 Handler", () => {
  it("should return 404 for unknown routes", async () => {
    const request = new Request("http://localhost/unknown-route");
    const ctx = createExecutionContext();
    const response = await app.fetch(request, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(404);
    const body = (await response.json()) as { error: string; code: string };
    expect(body.error).toBe("Not found");
    expect(body.code).toBe("NOT_FOUND");
  });
});
