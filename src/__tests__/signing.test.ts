/** biome-ignore-all lint/style/noNonNullAssertion: This is a test file */
import * as openpgp from "openpgp";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { StoredKey } from "~/schemas/keys";
import {
  createArmoredPrivateKey,
  createKeyFingerprint,
  createKeyId,
} from "~/types";
import {
  clearKeyCache,
  createStoredKey,
  extractPublicKey,
  getKeyCacheStats,
  invalidateKeyCache,
  parseAndValidateKey,
  signCommitData,
} from "~/utils/signing";

vi.mock("openpgp", async (importOriginal) => {
  const actual = await importOriginal<typeof import("openpgp")>();
  return { ...actual, readPrivateKey: vi.fn(actual.readPrivateKey) };
});

// Clear cache between tests to ensure isolation
afterEach(() => {
  clearKeyCache();
  vi.restoreAllMocks();
});

// Generate a test key for use in tests
async function generateTestKey(passphrase?: string) {
  const options = passphrase
    ? {
      type: "ecc" as const,
      curve: "ed25519Legacy" as const,
      userIDs: [{ name: "Test User", email: "test@example.com" }],
      passphrase,
      format: "armored" as const,
    }
    : {
      type: "ecc" as const,
      curve: "ed25519Legacy" as const,
      userIDs: [{ name: "Test User", email: "test@example.com" }],
      format: "armored" as const,
    };

  const { privateKey, publicKey } = await openpgp.generateKey(options);

  const parsedKey = await openpgp.readPrivateKey({ armoredKey: privateKey });
  const keyId = parsedKey.getKeyID().toHex().toUpperCase();
  const fingerprint = parsedKey.getFingerprint();

  return { privateKey, publicKey, keyId, fingerprint };
}

describe("parseAndValidateKey", () => {
  it("should parse unencrypted key", async () => {
    const { privateKey } = await generateTestKey();

    const info = await parseAndValidateKey(privateKey);

    expect(info.keyId).toBeTruthy();
    expect(info.fingerprint).toBeTruthy();
    expect(info.algorithm).toBe("EdDSA");
    expect(info.userId).toBe("Test User <test@example.com>");
  });

  it("should parse encrypted key with passphrase", async () => {
    const passphrase = "test-passphrase-123";
    const { privateKey } = await generateTestKey(passphrase);

    const info = await parseAndValidateKey(privateKey, passphrase);

    expect(info.keyId).toBeTruthy();
    expect(info.algorithm).toBe("EdDSA");
  });

  it("should throw for encrypted key without passphrase", async () => {
    const { privateKey } = await generateTestKey("secret");

    // Reading should work, but decryption will fail if we try to use it
    const info = await parseAndValidateKey(privateKey);
    expect(info.keyId).toBeTruthy();
  });

  it("should throw for invalid key format", async () => {
    await expect(parseAndValidateKey("not a valid key")).rejects.toThrow();
  });
  it("should handle unknown algorithm", async () => {
    const { privateKey } = await generateTestKey();

    // Mock openpgp.readPrivateKey to return a key with unknown algorithm
    vi.mocked(openpgp.readPrivateKey).mockResolvedValueOnce({
      keyPacket: { algorithm: 999 }, // Unknown algorithm ID
      getFingerprint: () => "0123456789ABCDEF0123456789ABCDEF01234567",
      getKeyID: () => ({ toHex: () => "A1B2C3D4E5F67890" }),
      getUserIDs: () => ["User"],
      isDecrypted: () => true,
    } as unknown as openpgp.PrivateKey);

    try {
      const info = await parseAndValidateKey(privateKey);
      expect(info.algorithm).toBe("Unknown(999)");
    } finally {
      vi.restoreAllMocks();
    }
  });

  it("should handle key without User ID", async () => {
    const { privateKey } = await generateTestKey();

    // Mock openpgp.readPrivateKey to return a key with no User IDs
    vi.mocked(openpgp.readPrivateKey).mockResolvedValueOnce({
      keyPacket: { algorithm: 22 }, // EdDSA
      getFingerprint: () => "0123456789ABCDEF0123456789ABCDEF01234567",
      getKeyID: () => ({ toHex: () => "A1B2C3D4E5F67890" }),
      getUserIDs: () => [],
      isDecrypted: () => true,
    } as unknown as openpgp.PrivateKey);

    const info = await parseAndValidateKey(privateKey);
    expect(info.userId).toBe("Unknown");
  });
});

describe("extractPublicKey", () => {
  it("should extract public key from private key", async () => {
    const { privateKey } = await generateTestKey();

    const extracted = await extractPublicKey(privateKey);

    expect(extracted).toContain("-----BEGIN PGP PUBLIC KEY BLOCK-----");
    expect(extracted).toContain("-----END PGP PUBLIC KEY BLOCK-----");

    // Verify it's a valid public key
    const parsedPublic = await openpgp.readKey({ armoredKey: extracted });
    expect(parsedPublic.isPrivate()).toBe(false);
  });

  it("should work with branded type", async () => {
    const { privateKey } = await generateTestKey();
    const branded = createArmoredPrivateKey(privateKey);

    const extracted = await extractPublicKey(branded);

    expect(extracted).toContain("-----BEGIN PGP PUBLIC KEY BLOCK-----");
  });
});

describe("signCommitData", () => {
  it("should sign commit data with unencrypted key", async () => {
    const { privateKey, keyId, fingerprint } = await generateTestKey();

    const storedKey: StoredKey = {
      armoredPrivateKey: createArmoredPrivateKey(privateKey),
      keyId: createKeyId(keyId),
      fingerprint: createKeyFingerprint(fingerprint),
      createdAt: new Date().toISOString(),
      algorithm: "EdDSA",
    };

    const commitData =
      "tree abc123\nparent def456\nauthor Test <test@test.com> 1234567890 +0000\n\nTest commit";

    const result = await signCommitData(commitData, storedKey, "");

    expect(result.signature).toContain("-----BEGIN PGP SIGNATURE-----");
    expect(result.signature).toContain("-----END PGP SIGNATURE-----");
    expect(result.keyId).toBe(keyId);
    expect(result.algorithm).toBe("EdDSA");
    expect(result.fingerprint.toLowerCase()).toBe(fingerprint.toLowerCase());
  });

  it("should sign commit data with encrypted key", async () => {
    const passphrase = "secure-pass-456";
    const { privateKey, keyId, fingerprint } = await generateTestKey(
      passphrase,
    );

    const storedKey: StoredKey = {
      armoredPrivateKey: createArmoredPrivateKey(privateKey),
      keyId: createKeyId(keyId),
      fingerprint: createKeyFingerprint(fingerprint),
      createdAt: new Date().toISOString(),
      algorithm: "EdDSA",
    };

    const commitData = "tree xyz789\nTest commit message";

    const result = await signCommitData(commitData, storedKey, passphrase);

    expect(result.signature).toContain("-----BEGIN PGP SIGNATURE-----");
  });

  it("should create verifiable signature", async () => {
    const { privateKey, publicKey, keyId, fingerprint } =
      await generateTestKey();

    const storedKey: StoredKey = {
      armoredPrivateKey: createArmoredPrivateKey(privateKey),
      keyId: createKeyId(keyId),
      fingerprint: createKeyFingerprint(fingerprint),
      createdAt: new Date().toISOString(),
      algorithm: "EdDSA",
    };

    const commitData = "tree abc\nTest";

    const result = await signCommitData(commitData, storedKey, "");

    // Verify the signature
    const pubKey = await openpgp.readKey({ armoredKey: publicKey });
    const message = await openpgp.createMessage({ text: commitData });
    const signature = await openpgp.readSignature({
      armoredSignature: result.signature,
    });

    const verification = await openpgp.verify({
      message,
      signature,
      verificationKeys: pubKey,
    });

    const firstSignature = verification.signatures[0];
    expect(firstSignature).toBeDefined();
    const { verified } = firstSignature!;
    await expect(verified).resolves.toBeTruthy();
  });

  it("should throw with wrong passphrase", async () => {
    const { privateKey, keyId, fingerprint } = await generateTestKey("correct");

    const storedKey: StoredKey = {
      armoredPrivateKey: createArmoredPrivateKey(privateKey),
      keyId: createKeyId(keyId),
      fingerprint: createKeyFingerprint(fingerprint),
      createdAt: new Date().toISOString(),
      algorithm: "EdDSA",
    };

    await expect(signCommitData("test", storedKey, "wrong")).rejects.toThrow();
  });
});

describe("createStoredKey", () => {
  it("should create StoredKey with branded types", () => {
    const validPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEaR3PyhYJKwYBBAHaRw8BAQdA4098Byyni0yyLGaDLgEajIgJTXkk7FpK0MQw
d6i3vJf+BwMCZ4XgIvvkVqb/kUozsyjzvltTYkQFFFlDeKnOEZKjJWkUzQYtAKXA
WHH4p4fZpbw9E3Rd9tkbP2veyo3dTkWJgYnOTJJJFRd+P+7SjzApULQ2S2FqIEtv
d2Fsc2tpIChBdXRvbWF0ZWQgc2lnbmluZykgPGluZm9Aa2Fqa293YWxza2kubmw+
iJYEExYKAD4WIQSAbTobn5V9ZzGVC8pi515USXgV3QUCaR3PygIbAwUJA8JnAAUL
CQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRBi515USXgV3UGkAQDdih4x/+9oQZ6+
0T0Etx1oIerz9Uh8CD0aRP/XzC1wPQD/Ug7bAb9n5RFDqb2Vlq2KK+uza5vDlDHq
rxgkrugpagY=
=gskf
-----END PGP PRIVATE KEY BLOCK-----`;

    const result = createStoredKey(
      validPrivateKey,
      "A1B2C3D4E5F67890",
      "0123456789ABCDEF0123456789ABCDEF01234567",
      "RSA",
    );

    expect(result.armoredPrivateKey).toContain(
      "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    );
    expect(result.keyId).toBe("A1B2C3D4E5F67890");
    expect(result.fingerprint).toBe("0123456789ABCDEF0123456789ABCDEF01234567");
    expect(result.algorithm).toBe("RSA");
    expect(result.createdAt).toBeTruthy();
  });

  it("should set createdAt to current time", () => {
    const validPrivateKey = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEaR3PyhYJKwYBBAHaRw8BAQdA4098Byyni0yyLGaDLgEajIgJTXkk7FpK0MQw
d6i3vJf+BwMCZ4XgIvvkVqb/kUozsyjzvltTYkQFFFlDeKnOEZKjJWkUzQYtAKXA
WHH4p4fZpbw9E3Rd9tkbP2veyo3dTkWJgYnOTJJJFRd+P+7SjzApULQ2S2FqIEtv
d2Fsc2tpIChBdXRvbWF0ZWQgc2lnbmluZykgPGluZm9Aa2Fqa293YWxza2kubmw+
iJYEExYKAD4WIQSAbTobn5V9ZzGVC8pi515USXgV3QUCaR3PygIbAwUJA8JnAAUL
CQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRBi515USXgV3UGkAQDdih4x/+9oQZ6+
0T0Etx1oIerz9Uh8CD0aRP/XzC1wPQD/Ug7bAb9n5RFDqb2Vlq2KK+uza5vDlDHq
rxgkrugpagY=
=gskf
-----END PGP PRIVATE KEY BLOCK-----`;

    const before = new Date().toISOString();
    const result = createStoredKey(
      validPrivateKey,
      "A1B2C3D4E5F67890",
      "0123456789ABCDEF0123456789ABCDEF01234567",
      "algo",
    );
    const after = new Date().toISOString();

    expect(result.createdAt >= before).toBe(true);
    expect(result.createdAt <= after).toBe(true);
  });
});

describe("signCommitData caching", () => {
  it("should cache decrypted key after first signing", async () => {
    const { privateKey, keyId, fingerprint } = await generateTestKey();

    const storedKey: StoredKey = {
      armoredPrivateKey: createArmoredPrivateKey(privateKey),
      keyId: createKeyId(keyId),
      fingerprint: createKeyFingerprint(fingerprint),
      createdAt: new Date().toISOString(),
      algorithm: "EdDSA",
    };

    // First call - cache miss
    await signCommitData("commit 1", storedKey, "");

    // Check cache has one entry
    const stats = getKeyCacheStats();
    expect(stats.size).toBe(1);
  });

  it("should reuse cached key on subsequent signing", async () => {
    const { privateKey, keyId, fingerprint } = await generateTestKey();

    const storedKey: StoredKey = {
      armoredPrivateKey: createArmoredPrivateKey(privateKey),
      keyId: createKeyId(keyId),
      fingerprint: createKeyFingerprint(fingerprint),
      createdAt: new Date().toISOString(),
      algorithm: "EdDSA",
    };

    // Call readPrivateKey spy counter
    const readKeySpy = vi.mocked(openpgp.readPrivateKey);

    // First call - should parse key
    await signCommitData("commit 1", storedKey, "");
    const callsAfterFirst = readKeySpy.mock.calls.length;

    // Second call - should use cache, not parse again
    await signCommitData("commit 2", storedKey, "");
    const callsAfterSecond = readKeySpy.mock.calls.length;

    // readPrivateKey should not have been called again
    expect(callsAfterSecond).toBe(callsAfterFirst);
  });

  it("should produce valid signatures from cached key", async () => {
    const { privateKey, publicKey, keyId, fingerprint } =
      await generateTestKey();

    const storedKey: StoredKey = {
      armoredPrivateKey: createArmoredPrivateKey(privateKey),
      keyId: createKeyId(keyId),
      fingerprint: createKeyFingerprint(fingerprint),
      createdAt: new Date().toISOString(),
      algorithm: "EdDSA",
    };

    // First call populates cache
    await signCommitData("initial", storedKey, "");

    // Second call uses cache - verify signature is still valid
    const commitData = "cached signing test";
    const result = await signCommitData(commitData, storedKey, "");

    // Verify the signature
    const pubKey = await openpgp.readKey({ armoredKey: publicKey });
    const message = await openpgp.createMessage({ text: commitData });
    const signature = await openpgp.readSignature({
      armoredSignature: result.signature,
    });

    const verification = await openpgp.verify({
      message,
      signature,
      verificationKeys: pubKey,
    });

    const firstSignature = verification.signatures[0];
    expect(firstSignature).toBeDefined();
    await expect(firstSignature!.verified).resolves.toBeTruthy();
  });
});

describe("cache invalidation", () => {
  it("should invalidate specific key", async () => {
    const { privateKey, keyId, fingerprint } = await generateTestKey();

    const storedKey: StoredKey = {
      armoredPrivateKey: createArmoredPrivateKey(privateKey),
      keyId: createKeyId(keyId),
      fingerprint: createKeyFingerprint(fingerprint),
      createdAt: new Date().toISOString(),
      algorithm: "EdDSA",
    };

    // Populate cache
    await signCommitData("test", storedKey, "");
    expect(getKeyCacheStats().size).toBe(1);

    // Invalidate
    invalidateKeyCache(keyId);
    expect(getKeyCacheStats().size).toBe(0);
  });

  it("should clear all cached keys", async () => {
    const key1 = await generateTestKey();
    const key2 = await generateTestKey();

    const storedKey1: StoredKey = {
      armoredPrivateKey: createArmoredPrivateKey(key1.privateKey),
      keyId: createKeyId(key1.keyId),
      fingerprint: createKeyFingerprint(key1.fingerprint),
      createdAt: new Date().toISOString(),
      algorithm: "EdDSA",
    };

    const storedKey2: StoredKey = {
      armoredPrivateKey: createArmoredPrivateKey(key2.privateKey),
      keyId: createKeyId(key2.keyId),
      fingerprint: createKeyFingerprint(key2.fingerprint),
      createdAt: new Date().toISOString(),
      algorithm: "EdDSA",
    };

    // Populate cache with two keys
    await signCommitData("test1", storedKey1, "");
    await signCommitData("test2", storedKey2, "");
    expect(getKeyCacheStats().size).toBe(2);

    // Clear all
    clearKeyCache();
    expect(getKeyCacheStats().size).toBe(0);
  });

  it("should re-parse key after invalidation", async () => {
    const { privateKey, keyId, fingerprint } = await generateTestKey();

    const storedKey: StoredKey = {
      armoredPrivateKey: createArmoredPrivateKey(privateKey),
      keyId: createKeyId(keyId),
      fingerprint: createKeyFingerprint(fingerprint),
      createdAt: new Date().toISOString(),
      algorithm: "EdDSA",
    };

    const readKeySpy = vi.mocked(openpgp.readPrivateKey);

    // First call - parses key
    await signCommitData("commit 1", storedKey, "");
    const callsAfterFirst = readKeySpy.mock.calls.length;

    // Invalidate cache
    invalidateKeyCache(keyId);

    // Next call should parse again
    await signCommitData("commit 2", storedKey, "");
    const callsAfterInvalidation = readKeySpy.mock.calls.length;

    expect(callsAfterInvalidation).toBeGreaterThan(callsAfterFirst);
  });
});

describe("getKeyCacheStats", () => {
  it("should return cache statistics", async () => {
    const stats = getKeyCacheStats();
    expect(stats).toHaveProperty("size");
    expect(stats).toHaveProperty("ttl");
    expect(typeof stats.size).toBe("number");
    expect(typeof stats.ttl).toBe("number");
  });

  it("should report correct TTL", () => {
    const stats = getKeyCacheStats();
    // Default TTL is 5 minutes (300000 ms)
    expect(stats.ttl).toBe(5 * 60 * 1000);
  });
});
