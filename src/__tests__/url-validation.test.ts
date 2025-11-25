/**
 * URL Validation Tests - SSRF Protection
 * Tests validateUrl function for preventing Server-Side Request Forgery
 */
import { describe, expect, it } from "vitest";
import { validateUrl } from "../utils/url-validation";

describe("url-validation", () => {
  describe("validateUrl", () => {
    describe("URL format validation", () => {
      it("should reject invalid URL format", async () => {
        await expect(validateUrl("not-a-url")).rejects.toThrow(
          "Invalid URL format",
        );
      });

      it("should reject empty string", async () => {
        await expect(validateUrl("")).rejects.toThrow("Invalid URL format");
      });

      it("should reject relative URLs", async () => {
        await expect(validateUrl("/path/to/resource")).rejects.toThrow(
          "Invalid URL format",
        );
      });

      it("should reject URLs without protocol", async () => {
        await expect(validateUrl("example.com/path")).rejects.toThrow(
          "Invalid URL format",
        );
      });
    });

    describe("protocol validation", () => {
      it("should reject HTTP URLs", async () => {
        await expect(validateUrl("http://example.com")).rejects.toThrow(
          "Only HTTPS URLs are allowed",
        );
      });

      it("should accept HTTPS URLs", async () => {
        await expect(
          validateUrl("https://example.com"),
        ).resolves.toBeUndefined();
      });

      it("should reject FTP URLs", async () => {
        await expect(validateUrl("ftp://example.com")).rejects.toThrow(
          "Only HTTPS URLs are allowed",
        );
      });

      it("should reject file URLs", async () => {
        await expect(validateUrl("file:///etc/passwd")).rejects.toThrow(
          "Only HTTPS URLs are allowed",
        );
      });
    });

    describe("cloud metadata protection", () => {
      it("should reject AWS metadata endpoint", async () => {
        await expect(
          validateUrl("https://169.254.169.254/latest/meta-data/"),
        ).rejects.toThrow("Access to cloud metadata endpoints is forbidden");
      });

      it("should reject GCP metadata endpoint", async () => {
        await expect(
          validateUrl("https://metadata.google.internal/computeMetadata/v1/"),
        ).rejects.toThrow("Access to cloud metadata endpoints is forbidden");
      });

      it("should reject GCP metadata subdomains", async () => {
        await expect(
          validateUrl("https://subdomain.metadata.google.internal/"),
        ).rejects.toThrow("Access to cloud metadata endpoints is forbidden");
      });
    });

    describe("IPv4 private range blocking", () => {
      it("should reject 10.0.0.0/8 range", async () => {
        await expect(validateUrl("https://10.0.0.1/")).rejects.toThrow(
          "Access to private IP range 10.0.0.0/8 is forbidden",
        );
      });

      it("should reject 10.255.255.255", async () => {
        await expect(validateUrl("https://10.255.255.255/")).rejects.toThrow(
          "Access to private IP range 10.0.0.0/8 is forbidden",
        );
      });

      it("should reject 172.16.0.0/12 range - lower bound", async () => {
        await expect(validateUrl("https://172.16.0.1/")).rejects.toThrow(
          "Access to private IP range 172.16.0.0/12 is forbidden",
        );
      });

      it("should reject 172.16.0.0/12 range - upper bound", async () => {
        await expect(validateUrl("https://172.31.255.255/")).rejects.toThrow(
          "Access to private IP range 172.16.0.0/12 is forbidden",
        );
      });

      it("should allow 172.15.0.1 (outside private range)", async () => {
        await expect(
          validateUrl("https://172.15.0.1/"),
        ).resolves.toBeUndefined();
      });

      it("should allow 172.32.0.1 (outside private range)", async () => {
        await expect(
          validateUrl("https://172.32.0.1/"),
        ).resolves.toBeUndefined();
      });

      it("should reject 192.168.0.0/16 range", async () => {
        await expect(validateUrl("https://192.168.1.1/")).rejects.toThrow(
          "Access to private IP range 192.168.0.0/16 is forbidden",
        );
      });

      it("should reject 192.168.255.255", async () => {
        await expect(validateUrl("https://192.168.255.255/")).rejects.toThrow(
          "Access to private IP range 192.168.0.0/16 is forbidden",
        );
      });

      it("should allow 192.167.1.1 (outside private range)", async () => {
        await expect(
          validateUrl("https://192.167.1.1/"),
        ).resolves.toBeUndefined();
      });
    });

    describe("localhost blocking", () => {
      it("should reject 127.0.0.1", async () => {
        await expect(validateUrl("https://127.0.0.1/")).rejects.toThrow(
          "Access to localhost 127.0.0.0/8 is forbidden",
        );
      });

      it("should reject 127.255.255.255", async () => {
        await expect(validateUrl("https://127.255.255.255/")).rejects.toThrow(
          "Access to localhost 127.0.0.0/8 is forbidden",
        );
      });
    });

    describe("link-local blocking", () => {
      it("should reject 169.254.0.1", async () => {
        await expect(validateUrl("https://169.254.0.1/")).rejects.toThrow(
          "Access to link-local range 169.254.0.0/16 is forbidden",
        );
      });

      it("should reject 169.254.255.255", async () => {
        await expect(validateUrl("https://169.254.255.255/")).rejects.toThrow(
          "Access to link-local range 169.254.0.0/16 is forbidden",
        );
      });
    });

    describe("special IP ranges", () => {
      it("should reject 0.0.0.0/8", async () => {
        await expect(validateUrl("https://0.0.0.1/")).rejects.toThrow(
          "Access to 0.0.0.0/8 is forbidden",
        );
      });

      it("should reject multicast 224.0.0.0/4", async () => {
        await expect(validateUrl("https://224.0.0.1/")).rejects.toThrow(
          "Access to multicast range is forbidden",
        );
      });

      it("should reject multicast 239.255.255.255", async () => {
        await expect(validateUrl("https://239.255.255.255/")).rejects.toThrow(
          "Access to multicast range is forbidden",
        );
      });

      it("should reject reserved 240.0.0.0/4", async () => {
        await expect(validateUrl("https://240.0.0.1/")).rejects.toThrow(
          "Access to reserved IP range is forbidden",
        );
      });

      it("should reject 255.255.255.255", async () => {
        await expect(validateUrl("https://255.255.255.255/")).rejects.toThrow(
          "Access to reserved IP range is forbidden",
        );
      });
    });

    describe("invalid IPv4 addresses", () => {
      it("should reject IPv4 with values > 255 (invalid URL)", async () => {
        // URL parser rejects 256.x.x.x as invalid hostname
        await expect(validateUrl("https://256.1.1.1/")).rejects.toThrow(
          "Invalid URL format",
        );
      });

      it("should reject IPv4 with negative values", async () => {
        await expect(validateUrl("https://1.-1.1.1/")).rejects.toThrow(
          "Invalid URL format",
        );
      });
    });

    describe("IPv6 blocking", () => {
      it("should reject IPv6 localhost ::1", async () => {
        await expect(validateUrl("https://[::1]/")).rejects.toThrow(
          "Access to IPv6 localhost ::1 is forbidden",
        );
      });

      it("should reject IPv6 private fc00::/7 (fc prefix)", async () => {
        await expect(validateUrl("https://[fc00::1]/")).rejects.toThrow(
          "Access to IPv6 private range fc00::/7 is forbidden",
        );
      });

      it("should reject IPv6 private fc00::/7 (fd prefix)", async () => {
        await expect(validateUrl("https://[fd00::1]/")).rejects.toThrow(
          "Access to IPv6 private range fc00::/7 is forbidden",
        );
      });

      it("should reject IPv6 link-local fe80::/10", async () => {
        await expect(validateUrl("https://[fe80::1]/")).rejects.toThrow(
          "Access to IPv6 link-local range fe80::/10 is forbidden",
        );
      });

      it("should reject IPv6 link-local fe9x", async () => {
        await expect(validateUrl("https://[fe90::1]/")).rejects.toThrow(
          "Access to IPv6 link-local range fe80::/10 is forbidden",
        );
      });

      it("should reject IPv6 link-local feax", async () => {
        await expect(validateUrl("https://[fea0::1]/")).rejects.toThrow(
          "Access to IPv6 link-local range fe80::/10 is forbidden",
        );
      });

      it("should reject IPv6 link-local febx", async () => {
        await expect(validateUrl("https://[feb0::1]/")).rejects.toThrow(
          "Access to IPv6 link-local range fe80::/10 is forbidden",
        );
      });

      it("should reject IPv6 multicast ff00::/8", async () => {
        await expect(validateUrl("https://[ff02::1]/")).rejects.toThrow(
          "Access to IPv6 multicast range is forbidden",
        );
      });

      it("should accept public IPv6 addresses", async () => {
        await expect(
          validateUrl("https://[2001:db8::1]/"),
        ).resolves.toBeUndefined();
      });

      it("should handle full-form IPv6 (no :: notation)", async () => {
        // Full form public IPv6
        await expect(
          validateUrl("https://[2001:0db8:0000:0000:0000:0000:0000:0001]/"),
        ).resolves.toBeUndefined();
      });

      it("should reject full-form IPv6 loopback", async () => {
        await expect(
          validateUrl("https://[0000:0000:0000:0000:0000:0000:0000:0001]/"),
        ).rejects.toThrow("Access to IPv6 localhost ::1 is forbidden");
      });

      it("should reject full-form IPv6 private", async () => {
        await expect(
          validateUrl("https://[fc00:0000:0000:0000:0000:0000:0000:0001]/"),
        ).rejects.toThrow("Access to IPv6 private range fc00::/7 is forbidden");
      });
    });

    describe("IPv4-mapped IPv6", () => {
      it("should reject IPv4-mapped localhost ::ffff:127.0.0.1", async () => {
        await expect(
          validateUrl("https://[::ffff:127.0.0.1]/"),
        ).rejects.toThrow("Access to localhost 127.0.0.0/8 is forbidden");
      });

      it("should reject IPv4-mapped private ::ffff:10.0.0.1", async () => {
        await expect(validateUrl("https://[::ffff:10.0.0.1]/")).rejects.toThrow(
          "Access to private IP range 10.0.0.0/8 is forbidden",
        );
      });

      it("should reject IPv4-mapped private ::ffff:192.168.1.1", async () => {
        await expect(
          validateUrl("https://[::ffff:192.168.1.1]/"),
        ).rejects.toThrow(
          "Access to private IP range 192.168.0.0/16 is forbidden",
        );
      });
    });

    describe("valid public URLs", () => {
      it("should accept github.com", async () => {
        await expect(
          validateUrl("https://github.com"),
        ).resolves.toBeUndefined();
      });

      it("should accept cloudflare.com", async () => {
        await expect(
          validateUrl("https://cloudflare.com"),
        ).resolves.toBeUndefined();
      });

      it("should accept URLs with paths", async () => {
        await expect(
          validateUrl("https://example.com/path/to/resource"),
        ).resolves.toBeUndefined();
      });

      it("should accept URLs with query strings", async () => {
        await expect(
          validateUrl("https://example.com?query=value"),
        ).resolves.toBeUndefined();
      });

      it("should accept URLs with ports", async () => {
        await expect(
          validateUrl("https://example.com:8443"),
        ).resolves.toBeUndefined();
      });

      it("should accept public IPv4 addresses", async () => {
        await expect(validateUrl("https://8.8.8.8/")).resolves.toBeUndefined();
      });

      it("should accept public IPv4 addresses with ports", async () => {
        await expect(
          validateUrl("https://1.1.1.1:443/"),
        ).resolves.toBeUndefined();
      });
    });

    describe("edge cases", () => {
      it("should handle URLs with userinfo", async () => {
        await expect(
          validateUrl("https://user:pass@example.com"),
        ).resolves.toBeUndefined();
      });

      it("should handle URLs with fragments", async () => {
        await expect(
          validateUrl("https://example.com#fragment"),
        ).resolves.toBeUndefined();
      });

      it("should handle internationalized domain names", async () => {
        await expect(
          validateUrl("https://xn--n3h.com"),
        ).resolves.toBeUndefined();
      });
    });
  });
});
