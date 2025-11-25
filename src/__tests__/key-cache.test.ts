import * as openpgp from "openpgp";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TIME } from "~/types";
import { DecryptedKeyCache } from "~/utils/key-cache";

// Generate a mock private key for testing
async function generateMockKey(): Promise<openpgp.PrivateKey> {
  const { privateKey } = await openpgp.generateKey({
    type: "ecc",
    curve: "ed25519Legacy",
    userIDs: [{ name: "Test User", email: "test@example.com" }],
    format: "armored",
  });
  return openpgp.readPrivateKey({ armoredKey: privateKey });
}

describe("DecryptedKeyCache", () => {
  let cache: DecryptedKeyCache;

  beforeEach(() => {
    vi.useFakeTimers();
    cache = new DecryptedKeyCache(5 * TIME.MINUTE);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("get/set operations", () => {
    it("should return null for non-existent key", () => {
      const result = cache.get("non-existent-key");
      expect(result).toBeNull();
    });

    it("should store and retrieve a key", async () => {
      const mockKey = await generateMockKey();
      cache.set("test-key-id", mockKey);

      const result = cache.get("test-key-id");
      expect(result).toBe(mockKey);
    });

    it("should store multiple keys independently", async () => {
      const key1 = await generateMockKey();
      const key2 = await generateMockKey();

      cache.set("key-1", key1);
      cache.set("key-2", key2);

      expect(cache.get("key-1")).toBe(key1);
      expect(cache.get("key-2")).toBe(key2);
    });

    it("should overwrite existing key with same ID", async () => {
      const key1 = await generateMockKey();
      const key2 = await generateMockKey();

      cache.set("same-id", key1);
      cache.set("same-id", key2);

      expect(cache.get("same-id")).toBe(key2);
    });
  });

  describe("TTL expiration", () => {
    it("should return key before TTL expires", async () => {
      const mockKey = await generateMockKey();
      cache.set("test-key", mockKey);

      // Advance time by 4 minutes (less than 5 minute TTL)
      vi.advanceTimersByTime(4 * TIME.MINUTE);

      expect(cache.get("test-key")).toBe(mockKey);
    });

    it("should return null after TTL expires", async () => {
      const mockKey = await generateMockKey();
      cache.set("test-key", mockKey);

      // Advance time past TTL
      vi.advanceTimersByTime(5 * TIME.MINUTE + 1);

      expect(cache.get("test-key")).toBeNull();
    });

    it("should clean up expired entry on get", async () => {
      const mockKey = await generateMockKey();
      cache.set("test-key", mockKey);

      // Advance time past TTL
      vi.advanceTimersByTime(5 * TIME.MINUTE + 1);

      // First get returns null and should clean up
      expect(cache.get("test-key")).toBeNull();

      // Internal map should be cleaned
      const stats = cache.stats();
      expect(stats.size).toBe(0);
    });

    it("should use custom TTL from constructor", async () => {
      const shortCache = new DecryptedKeyCache(1 * TIME.MINUTE);
      const mockKey = await generateMockKey();

      shortCache.set("test-key", mockKey);

      // After 30 seconds, should still be valid
      vi.advanceTimersByTime(30 * TIME.SECOND);
      expect(shortCache.get("test-key")).toBe(mockKey);

      // After 1 minute + 1ms, should be expired
      vi.advanceTimersByTime(30 * TIME.SECOND + 1);
      expect(shortCache.get("test-key")).toBeNull();
    });

    it("should reset TTL when key is re-set", async () => {
      const mockKey = await generateMockKey();

      cache.set("test-key", mockKey);

      // Advance 4 minutes
      vi.advanceTimersByTime(4 * TIME.MINUTE);

      // Re-set the same key (resets TTL)
      cache.set("test-key", mockKey);

      // Advance another 4 minutes (total 8, but TTL reset at 4)
      vi.advanceTimersByTime(4 * TIME.MINUTE);

      // Should still be valid (4 minutes since reset, TTL is 5)
      expect(cache.get("test-key")).toBe(mockKey);
    });
  });

  describe("invalidation", () => {
    it("should invalidate specific key", async () => {
      const key1 = await generateMockKey();
      const key2 = await generateMockKey();

      cache.set("key-1", key1);
      cache.set("key-2", key2);

      cache.invalidate("key-1");

      expect(cache.get("key-1")).toBeNull();
      expect(cache.get("key-2")).toBe(key2);
    });

    it("should handle invalidating non-existent key", () => {
      // Should not throw
      expect(() => cache.invalidate("non-existent")).not.toThrow();
    });

    it("should clear all keys", async () => {
      const key1 = await generateMockKey();
      const key2 = await generateMockKey();

      cache.set("key-1", key1);
      cache.set("key-2", key2);

      cache.clear();

      expect(cache.get("key-1")).toBeNull();
      expect(cache.get("key-2")).toBeNull();
      expect(cache.stats().size).toBe(0);
    });
  });

  describe("stats", () => {
    it("should return correct size and TTL", async () => {
      const key1 = await generateMockKey();
      const key2 = await generateMockKey();

      cache.set("key-1", key1);
      cache.set("key-2", key2);

      const stats = cache.stats();
      expect(stats.size).toBe(2);
      expect(stats.ttl).toBe(5 * TIME.MINUTE);
    });

    it("should clean expired entries when getting stats", async () => {
      const key1 = await generateMockKey();
      const key2 = await generateMockKey();

      cache.set("key-1", key1);

      // Advance 3 minutes
      vi.advanceTimersByTime(3 * TIME.MINUTE);

      // Add another key (will expire later)
      cache.set("key-2", key2);

      // Advance 3 more minutes (key-1 expired, key-2 still valid)
      vi.advanceTimersByTime(3 * TIME.MINUTE);

      const stats = cache.stats();
      expect(stats.size).toBe(1); // Only key-2 remains
    });

    it("should return 0 size for empty cache", () => {
      const stats = cache.stats();
      expect(stats.size).toBe(0);
    });
  });

  describe("edge cases", () => {
    it("should handle empty string key ID", async () => {
      const mockKey = await generateMockKey();
      cache.set("", mockKey);
      expect(cache.get("")).toBe(mockKey);
    });

    it("should handle special characters in key ID", async () => {
      const mockKey = await generateMockKey();
      const specialKeyId = "key/with:special@chars#123";
      cache.set(specialKeyId, mockKey);
      expect(cache.get(specialKeyId)).toBe(mockKey);
    });

    it("should be independent between instances", async () => {
      const cache2 = new DecryptedKeyCache(5 * TIME.MINUTE);
      const mockKey = await generateMockKey();

      cache.set("shared-id", mockKey);

      expect(cache.get("shared-id")).toBe(mockKey);
      expect(cache2.get("shared-id")).toBeNull();
    });
  });
});
