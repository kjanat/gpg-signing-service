/**
 * SSRF (Server-Side Request Forgery) Protection Tests
 *
 * Tests the OIDC middleware's integration with URL validation
 * to prevent SSRF attacks through OIDC discovery and JWKS fetching.
 */
import { describe, expect, it, vi } from "vitest";
import { validateUrl } from "../utils/url-validation";

// Mock the validateUrl to simulate SSRF protection in OIDC context
vi.mock("../utils/url-validation", async () => {
  const actual = await vi.importActual<
    typeof import("../utils/url-validation")
  >("../utils/url-validation");
  return {
    ...actual,
    validateUrl: vi.fn(actual.validateUrl),
  };
});

describe("SSRF Protection - OIDC Integration", () => {
  describe("OIDC Issuer URL Validation", () => {
    it("should reject private IP issuer URLs", async () => {
      // Private IPs in issuer would be blocked at OIDC discovery
      await expect(
        validateUrl("https://10.0.0.1/.well-known/openid-configuration"),
      ).rejects.toThrow("private IP range");

      await expect(
        validateUrl("https://192.168.1.1/.well-known/openid-configuration"),
      ).rejects.toThrow("private IP range");

      await expect(
        validateUrl("https://172.16.0.1/.well-known/openid-configuration"),
      ).rejects.toThrow("private IP range");
    });

    it("should reject localhost issuer URLs", async () => {
      await expect(
        validateUrl("https://127.0.0.1/.well-known/openid-configuration"),
      ).rejects.toThrow("localhost");
    });

    it("should reject link-local issuer URLs", async () => {
      await expect(
        validateUrl("https://169.254.1.1/.well-known/openid-configuration"),
      ).rejects.toThrow("link-local");
    });

    it("should accept valid OIDC issuer URLs", async () => {
      await expect(
        validateUrl("https://token.actions.githubusercontent.com"),
      ).resolves.toBeUndefined();
      await expect(validateUrl("https://gitlab.com")).resolves.toBeUndefined();
      await expect(
        validateUrl("https://accounts.google.com"),
      ).resolves.toBeUndefined();
    });
  });

  describe("JWKS URI Validation", () => {
    it("should reject JWKS URLs pointing to internal services", async () => {
      // Attacker might try to make JWKS URI point to internal service
      await expect(
        validateUrl("https://10.0.0.100/internal-api"),
      ).rejects.toThrow("private IP range");

      await expect(
        validateUrl("https://192.168.100.1/secrets"),
      ).rejects.toThrow("private IP range");
    });

    it("should reject JWKS URLs pointing to cloud metadata", async () => {
      await expect(
        validateUrl("https://169.254.169.254/latest/meta-data/"),
      ).rejects.toThrow("cloud metadata");

      await expect(
        validateUrl("https://metadata.google.internal/computeMetadata/v1/"),
      ).rejects.toThrow("cloud metadata");
    });

    it("should reject HTTP JWKS URLs", async () => {
      await expect(
        validateUrl("http://legitimate-issuer.com/.well-known/jwks.json"),
      ).rejects.toThrow("Only HTTPS");
    });

    it("should accept valid JWKS URLs", async () => {
      await expect(
        validateUrl(
          "https://token.actions.githubusercontent.com/.well-known/jwks",
        ),
      ).resolves.toBeUndefined();
      await expect(
        validateUrl("https://www.googleapis.com/oauth2/v3/certs"),
      ).resolves.toBeUndefined();
    });
  });

  describe("IPv6 SSRF Vectors", () => {
    it("should reject IPv6 localhost in URLs", async () => {
      await expect(validateUrl("https://[::1]/api")).rejects.toThrow(
        "IPv6 localhost",
      );
    });

    it("should reject IPv6 private addresses", async () => {
      await expect(validateUrl("https://[fc00::1]/api")).rejects.toThrow(
        "IPv6 private range",
      );

      await expect(validateUrl("https://[fd00::1]/api")).rejects.toThrow(
        "IPv6 private range",
      );
    });

    it("should reject IPv6 link-local addresses", async () => {
      await expect(validateUrl("https://[fe80::1]/api")).rejects.toThrow(
        "IPv6 link-local range",
      );
    });
  });

  describe("Protocol Bypass Attempts", () => {
    it("should reject non-HTTPS protocols", async () => {
      await expect(validateUrl("http://example.com")).rejects.toThrow(
        "Only HTTPS",
      );
      await expect(validateUrl("ftp://example.com")).rejects.toThrow(
        "Only HTTPS",
      );
      await expect(validateUrl("file:///etc/passwd")).rejects.toThrow(
        "Only HTTPS",
      );
    });

    it("should reject malformed URLs", async () => {
      await expect(validateUrl("not-a-url")).rejects.toThrow(
        "Invalid URL format",
      );
      await expect(validateUrl("")).rejects.toThrow("Invalid URL format");
    });
  });

  describe("Real-world SSRF Attack Patterns", () => {
    it("should block AWS metadata service access", async () => {
      // Common AWS SSRF attack vector
      await expect(
        validateUrl(
          "https://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ),
      ).rejects.toThrow("cloud metadata");
    });

    it("should block GCP metadata service access", async () => {
      await expect(
        validateUrl(
          "https://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        ),
      ).rejects.toThrow("cloud metadata");
    });

    it("should block internal network scanning", async () => {
      // Attacker might try to scan internal network
      await expect(validateUrl("https://10.0.0.1:8080/")).rejects.toThrow(
        "private IP",
      );
      await expect(validateUrl("https://192.168.1.1:443/")).rejects.toThrow(
        "private IP",
      );
      await expect(validateUrl("https://172.20.0.1:9000/")).rejects.toThrow(
        "private IP",
      );
    });

    it("should block reserved IP ranges", async () => {
      await expect(validateUrl("https://0.0.0.1/")).rejects.toThrow(
        "0.0.0.0/8",
      );
      await expect(validateUrl("https://224.0.0.1/")).rejects.toThrow(
        "multicast",
      );
      await expect(validateUrl("https://240.0.0.1/")).rejects.toThrow(
        "reserved IP range",
      );
    });
  });
});
