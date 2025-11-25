/**
 * SSRF Protection: URL validation utility
 * Prevents Server-Side Request Forgery by blocking private/internal networks
 */

/**
 * Validates URL to prevent SSRF attacks
 * @throws {Error} if URL points to private/internal network
 */
export async function validateUrl(url: string): Promise<void> {
  let parsedUrl: URL;

  try {
    parsedUrl = new URL(url);
  } catch {
    throw new Error("Invalid URL format");
  }

  // Only allow HTTPS
  if (parsedUrl.protocol !== "https:") {
    throw new Error("Only HTTPS URLs are allowed");
  }

  // Block common cloud metadata endpoints
  if (
    parsedUrl.hostname === "169.254.169.254"
    || parsedUrl.hostname === "metadata.google.internal"
    || parsedUrl.hostname.endsWith(".metadata.google.internal")
  ) {
    throw new Error("Access to cloud metadata endpoints is forbidden");
  }

  // Check if hostname is IP address
  const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6Pattern = /^\[?([0-9a-fA-F:]+)]?$/;

  if (ipv4Pattern.test(parsedUrl.hostname)) {
    validateIPv4(parsedUrl.hostname);
  } else if (ipv6Pattern.test(parsedUrl.hostname)) {
    const ipv6 = parsedUrl.hostname.replace(/[[\]]/g, "");
    validateIPv6(ipv6);
  }

  // Note: DNS resolution to check if domain resolves to private IP
  // is not feasible in Cloudflare Workers without external service.
  // This provides basic protection against direct IP usage.
}

/**
 * Validates IPv4 address against private ranges
 */
function validateIPv4(ip: string): void {
  const parts = ip.split(".").map(Number);

  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    throw new Error("Invalid IPv4 address");
  }

  // parts is guaranteed to have 4 valid numbers after the check above
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const a = parts[0]!;
  const b = parts[1];

  // 10.0.0.0/8 - Private
  if (a === 10) {
    throw new Error("Access to private IP range 10.0.0.0/8 is forbidden");
  }

  // 172.16.0.0/12 - Private
  if (a === 172 && b !== undefined && b >= 16 && b <= 31) {
    throw new Error("Access to private IP range 172.16.0.0/12 is forbidden");
  }

  // 192.168.0.0/16 - Private
  if (a === 192 && b === 168) {
    throw new Error("Access to private IP range 192.168.0.0/16 is forbidden");
  }

  // 127.0.0.0/8 - Loopback
  if (a === 127) {
    throw new Error("Access to localhost 127.0.0.0/8 is forbidden");
  }

  // 169.254.0.0/16 - Link-local
  if (a === 169 && b === 254) {
    throw new Error("Access to link-local range 169.254.0.0/16 is forbidden");
  }

  // 0.0.0.0/8 - Current network
  if (a === 0) {
    throw new Error("Access to 0.0.0.0/8 is forbidden");
  }

  // 224.0.0.0/4 - Multicast
  if (a >= 224 && a <= 239) {
    throw new Error("Access to multicast range is forbidden");
  }

  // 240.0.0.0/4 - Reserved
  if (a >= 240) {
    throw new Error("Access to reserved IP range is forbidden");
  }
}

/**
 * Validates IPv6 address against private ranges
 */
function validateIPv6(ip: string): void {
  const normalized = normalizeIPv6(ip);

  // ::1 - Loopback
  if (normalized === "0000:0000:0000:0000:0000:0000:0000:0001") {
    throw new Error("Access to IPv6 localhost ::1 is forbidden");
  }

  // fc00::/7 - Unique Local Addresses (private)
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) {
    throw new Error("Access to IPv6 private range fc00::/7 is forbidden");
  }

  // fe80::/10 - Link-local
  if (
    normalized.startsWith("fe8")
    || normalized.startsWith("fe9")
    || normalized.startsWith("fea")
    || normalized.startsWith("feb")
  ) {
    throw new Error("Access to IPv6 link-local range fe80::/10 is forbidden");
  }

  // ff00::/8 - Multicast
  if (normalized.startsWith("ff")) {
    throw new Error("Access to IPv6 multicast range is forbidden");
  }

  // ::ffff:0:0/96 - IPv4-mapped IPv6 (check embedded IPv4)
  if (normalized.startsWith("0000:0000:0000:0000:0000:ffff:")) {
    const ipv4Part = normalized.slice(30); // Get last part
    const ipv4Hex = [
      ipv4Part.slice(0, 2),
      ipv4Part.slice(2, 4),
      ipv4Part.slice(5, 7),
      ipv4Part.slice(7, 9),
    ];
    const ipv4 = ipv4Hex.map((hex) => parseInt(hex, 16)).join(".");
    validateIPv4(ipv4);
  }
}

/**
 * Normalize IPv6 address to full form
 */
function normalizeIPv6(ip: string): string {
  // Expand :: notation
  const parts = ip.split("::");
  if (parts.length === 2) {
    const left = parts[0] ? parts[0].split(":") : [];
    const right = parts[1] ? parts[1].split(":") : [];
    const missing = 8 - left.length - right.length;
    const middle = Array(missing).fill("0000");
    return [...left, ...middle, ...right]
      .map((p) => p.padStart(4, "0"))
      .join(":");
  }

  // Already full form
  return ip
    .split(":")
    .map((p) => p.padStart(4, "0"))
    .join(":");
}
