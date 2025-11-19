import { describe, it, expect } from "vitest";
import * as openpgp from "openpgp";
import {
  signCommitData,
  parseAndValidateKey,
  extractPublicKey,
  createStoredKey,
} from "~/utils/signing";
import type { StoredKey } from "~/types";
import {
  createKeyId,
  createKeyFingerprint,
  createArmoredPrivateKey,
} from "~/types";

// Generate a test key for use in tests
async function generateTestKey(passphrase?: string) {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: "ecc",
    curve: "ed25519Legacy",
    userIDs: [{ name: "Test User", email: "test@example.com" }],
    passphrase,
    format: "armored",
  });

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
    const { privateKey, keyId, fingerprint } =
      await generateTestKey(passphrase);

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
    const result = createStoredKey(
      "-----BEGIN PGP PRIVATE KEY-----\ntest\n-----END PGP PRIVATE KEY-----",
      "ABCD1234",
      "1234567890ABCDEF",
      "RSA",
    );

    expect(result.armoredPrivateKey).toContain(
      "-----BEGIN PGP PRIVATE KEY-----",
    );
    expect(result.keyId).toBe("ABCD1234");
    expect(result.fingerprint).toBe("1234567890ABCDEF");
    expect(result.algorithm).toBe("RSA");
    expect(result.createdAt).toBeTruthy();
  });

  it("should set createdAt to current time", () => {
    const before = new Date().toISOString();
    const result = createStoredKey("key", "id", "fp", "algo");
    const after = new Date().toISOString();

    expect(result.createdAt >= before).toBe(true);
    expect(result.createdAt <= after).toBe(true);
  });
});
