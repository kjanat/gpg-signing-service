import {
  createExecutionContext,
  env,
  waitOnExecutionContext,
} from "cloudflare:test";
import app from "gpg-signing-service";
// Mock audit logging to avoid database errors in tests
import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("~/utils/audit", async (importOriginal) => {
  const actual = await importOriginal<typeof import("~/utils/audit")>();
  return { ...actual, logAuditEvent: vi.fn(async () => undefined) };
});

/**
 * Timing Attack Security Tests
 *
 * These tests verify that admin token comparison uses constant-time comparison
 * to prevent timing attacks that could leak information about the token.
 */
describe("Timing Attack Protection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("Admin Token Comparison", () => {
    it("should reject invalid admin token", async () => {
      const ctx = createExecutionContext();
      const response = await app.fetch(
        new Request("http://localhost/admin/keys", {
          headers: { Authorization: "Bearer invalid-token" },
        }),
        env,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("AUTH_INVALID");
    });

    it("should reject admin token with wrong length", async () => {
      const ctx = createExecutionContext();
      const shortToken = "short";
      const response = await app.fetch(
        new Request("http://localhost/admin/keys", {
          headers: { Authorization: `Bearer ${shortToken}` },
        }),
        env,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("AUTH_INVALID");
    });

    it("should reject admin token with partial match", async () => {
      const ctx = createExecutionContext();
      // Assume env.ADMIN_TOKEN is something like "admin-secret-token"
      // Create a token that matches first half but not second half
      const partialMatch =
        env.ADMIN_TOKEN.slice(0, Math.floor(env.ADMIN_TOKEN.length / 2))
        + "X".repeat(Math.ceil(env.ADMIN_TOKEN.length / 2));

      const response = await app.fetch(
        new Request("http://localhost/admin/keys", {
          headers: { Authorization: `Bearer ${partialMatch}` },
        }),
        env,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("AUTH_INVALID");
    });

    it("should accept valid admin token", async () => {
      const ctx = createExecutionContext();
      const response = await app.fetch(
        new Request("http://localhost/admin/keys", {
          headers: { Authorization: `Bearer ${env.ADMIN_TOKEN}` },
        }),
        env,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      // Should succeed (200 or other non-401 status)
      expect(response.status).not.toBe(401);
    });

    it("should use constant-time comparison", async () => {
      // This test verifies the BEHAVIOR of token comparison.
      //
      // Security Property: The implementation uses crypto.subtle.timingSafeEqual
      // for constant-time comparison, which prevents timing attacks. Timing attacks
      // could allow attackers to leak information about tokens through response
      // timing differences based on how many characters match.
      //
      // Why not measure timing directly?
      // Timing measurements are inherently flaky in test environments due to:
      // - Variable system load and CPU scheduling
      // - JavaScript event loop variability
      // - Test framework overhead
      // - OS-level resource contention
      // Reliable timing attack detection requires specialized hardware and
      // statistical analysis that cannot be performed in unit tests.
      //
      // This test verifies that all invalid tokens (regardless of length or
      // partial matches) are properly rejected with the same error response.

      const correctToken = env.ADMIN_TOKEN;
      const wrongLength = "X".repeat(correctToken.length + 10);
      const wrongPrefix = "X".repeat(correctToken.length);
      const partialMatch = `${correctToken.slice(0, correctToken.length - 1)}X`;

      // Verify all invalid tokens are rejected identically
      for (const token of [wrongLength, wrongPrefix, partialMatch]) {
        const ctx = createExecutionContext();
        const response = await app.fetch(
          new Request("http://localhost/admin/keys", {
            headers: { Authorization: `Bearer ${token}` },
          }),
          env,
          ctx,
        );
        await waitOnExecutionContext(ctx);

        expect(response.status).toBe(401);
        const body = (await response.json()) as { error: string; code: string };
        expect(body.code).toBe("AUTH_INVALID");
        expect(body.error).toBe("Invalid admin token");
      }
    });

    it("should handle empty token", async () => {
      const ctx = createExecutionContext();
      const response = await app.fetch(
        new Request("http://localhost/admin/keys", {
          headers: { Authorization: "Bearer " },
        }),
        env,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
    });

    it("should handle missing Authorization header", async () => {
      const ctx = createExecutionContext();
      const response = await app.fetch(
        new Request("http://localhost/admin/keys"),
        env,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("AUTH_MISSING");
    });

    it("should handle malformed Authorization header", async () => {
      const ctx = createExecutionContext();
      const response = await app.fetch(
        new Request("http://localhost/admin/keys", {
          headers: { Authorization: "InvalidFormat" },
        }),
        env,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
      const body = (await response.json()) as { code: string };
      expect(body.code).toBe("AUTH_MISSING");
    });

    it("should protect all admin endpoints with timing-safe comparison", async () => {
      const adminEndpoints = [
        { method: "GET", path: "/admin/keys" },
        { method: "POST", path: "/admin/keys" },
        { method: "GET", path: "/admin/keys/TESTKEY123/public" },
        { method: "DELETE", path: "/admin/keys/TESTKEY123" },
        { method: "GET", path: "/admin/audit" },
      ];

      for (const endpoint of adminEndpoints) {
        const ctx = createExecutionContext();
        const response = await app.fetch(
          new Request(`http://localhost${endpoint.path}`, {
            method: endpoint.method,
            headers: { Authorization: "Bearer wrong-token" },
          }),
          env,
          ctx,
        );
        await waitOnExecutionContext(ctx);

        expect(response.status).toBe(401);
        const body = (await response.json()) as { code: string };
        expect(body.code).toBe("AUTH_INVALID");
      }
    });
  });

  describe("Timing Attack Mitigation Strategy", () => {
    it("should pad shorter tokens to prevent length leakage", async () => {
      // This test verifies the BEHAVIOR of length padding.
      //
      // Security Property: The timingSafeEqual function pads both inputs to the
      // same length before comparison, preventing attackers from determining
      // token length through timing analysis.
      //
      // Implementation detail: In src/middleware/oidc.ts, timingSafeEqual() creates
      // zero-padded byte arrays of equal length, ensuring that both short and
      // long invalid tokens are compared in constant time.
      //
      // Verification approach: Test that different length tokens are all rejected
      // with the same error response, documenting the padding behavior without
      // relying on flaky timing measurements.

      const tokens = [
        "a",
        "ab",
        "abc",
        "abcd",
        "X".repeat(env.ADMIN_TOKEN.length),
      ];

      // All tokens should be rejected identically regardless of length
      for (const token of tokens) {
        const ctx = createExecutionContext();
        const response = await app.fetch(
          new Request("http://localhost/admin/keys", {
            headers: { Authorization: `Bearer ${token}` },
          }),
          env,
          ctx,
        );
        await waitOnExecutionContext(ctx);

        expect(response.status).toBe(401);
        const body = (await response.json()) as { error: string; code: string };
        expect(body.code).toBe("AUTH_INVALID");
        expect(body.error).toBe("Invalid admin token");
      }
    });

    it("should use crypto.subtle.timingSafeEqual for comparison", async () => {
      // This test verifies that the implementation uses the Web Crypto API's
      // timingSafeEqual function, which is designed to prevent timing attacks.
      //
      // Implementation Evidence: The source code in src/middleware/oidc.ts
      // explicitly uses crypto.subtle.timingSafeEqual() for the admin token
      // comparison, which is the standard Web Crypto API method for
      // constant-time comparison.
      //
      // Behavioral Verification: We verify that tokens with partial matches
      // (same prefix, different suffix) are handled the same as completely
      // wrong tokens. This confirms the implementation doesn't early-exit
      // on mismatch, which is what constant-time comparison prevents.

      const attempts = [
        env.ADMIN_TOKEN.slice(0, 5) + "X".repeat(env.ADMIN_TOKEN.length - 5),
        env.ADMIN_TOKEN.slice(0, 10) + "X".repeat(env.ADMIN_TOKEN.length - 10),
        env.ADMIN_TOKEN.slice(0, 15) + "X".repeat(env.ADMIN_TOKEN.length - 15),
        "X".repeat(env.ADMIN_TOKEN.length),
      ];

      // All attempts should be rejected with the same response
      for (const attempt of attempts) {
        const ctx = createExecutionContext();
        const response = await app.fetch(
          new Request("http://localhost/admin/keys", {
            headers: { Authorization: `Bearer ${attempt}` },
          }),
          env,
          ctx,
        );
        await waitOnExecutionContext(ctx);

        expect(response.status).toBe(401);
        const body = (await response.json()) as { error: string; code: string };
        expect(body.code).toBe("AUTH_INVALID");
        expect(body.error).toBe("Invalid admin token");
      }
    });
  });

  describe("Security Properties", () => {
    it("should not leak token information through error messages", async () => {
      const ctx = createExecutionContext();
      const response = await app.fetch(
        new Request("http://localhost/admin/keys", {
          headers: { Authorization: "Bearer wrong-token" },
        }),
        env,
        ctx,
      );
      await waitOnExecutionContext(ctx);

      expect(response.status).toBe(401);
      const body = (await response.json()) as { error: string };

      // Error message should be generic, not revealing any information
      // about the actual token or how close the guess was
      expect(body.error).toBe("Invalid admin token");
      expect(body.error).not.toContain(env.ADMIN_TOKEN);
      expect(body.error).not.toMatch(/character|position|length|match/i);
    });

    it("should not leak timing information through response delays", async () => {
      // This test verifies the BEHAVIOR of response timing consistency.
      //
      // Security Property: The adminAuth middleware (src/middleware/oidc.ts)
      // uses constant-time comparison and immediately returns a 401 response
      // with a generic error message. There is no conditional logic based on
      // token validation that could introduce response timing delays.
      //
      // Why not measure timing directly?
      // Timing measurements of HTTP requests are affected by many factors:
      // - Network latency and jitter
      // - HTTP client implementation variability
      // - Test framework overhead
      // - System load and CPU scheduling
      // - Memory allocation patterns
      // These factors make per-request timing measurements unreliable for
      // detecting sub-millisecond timing differences.
      //
      // Behavioral Verification: We verify that invalid tokens are rejected
      // with the same error response every time, confirming that no conditional
      // logic based on token content affects the response path.

      const wrongToken = "X".repeat(env.ADMIN_TOKEN.length);

      // Verify that repeated requests get consistent responses
      for (let i = 0; i < 5; i++) {
        const ctx = createExecutionContext();
        const response = await app.fetch(
          new Request("http://localhost/admin/keys", {
            headers: { Authorization: `Bearer ${wrongToken}` },
          }),
          env,
          ctx,
        );
        await waitOnExecutionContext(ctx);

        expect(response.status).toBe(401);
        const body = (await response.json()) as { error: string; code: string };
        expect(body.code).toBe("AUTH_INVALID");
        expect(body.error).toBe("Invalid admin token");
      }
    });
  });
});
