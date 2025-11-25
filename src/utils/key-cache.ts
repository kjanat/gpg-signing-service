import type * as openpgp from "openpgp";
import { CACHE_TTL } from "./constants";

/**
 * Cache entry for a decrypted OpenPGP private key
 */
interface CacheEntry {
  key: openpgp.PrivateKey;
  expiresAt: number;
}

/**
 * Time-based cache for decrypted OpenPGP private keys
 *
 * Design considerations:
 * - In-memory only (no persistence) for security
 * - Time-based eviction to limit exposure of decrypted keys
 * - Simple Map-based storage (LRU not needed for small key counts)
 * - Thread-safe within single DO instance (JS is single-threaded)
 */
export class DecryptedKeyCache {
  private cache = new Map<string, CacheEntry>();
  private readonly ttl: number;

  constructor(ttl: number = CACHE_TTL.DECRYPTED_KEY) {
    this.ttl = ttl;
  }

  /**
   * Get a cached decrypted key if it exists and hasn't expired
   */
  get(keyId: string): openpgp.PrivateKey | null {
    const entry = this.cache.get(keyId);

    if (!entry) {
      return null;
    }

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(keyId);
      return null;
    }

    return entry.key;
  }

  /**
   * Store a decrypted key in the cache
   */
  set(keyId: string, key: openpgp.PrivateKey): void {
    this.cache.set(keyId, {
      key,
      expiresAt: Date.now() + this.ttl,
    });
  }

  /**
   * Invalidate a specific key from the cache
   */
  invalidate(keyId: string): void {
    this.cache.delete(keyId);
  }

  /**
   * Invalidate all cached keys
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Get cache statistics (for monitoring)
   */
  stats(): { size: number; ttl: number } {
    // Clean expired entries first
    const now = Date.now();
    for (const [keyId, entry] of this.cache) {
      if (now > entry.expiresAt) {
        this.cache.delete(keyId);
      }
    }
    return { size: this.cache.size, ttl: this.ttl };
  }
}
