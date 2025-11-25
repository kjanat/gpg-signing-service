# ADR-002: OpenPGP.js for Cryptographic Operations

## Status

Accepted

## Context

The service signs Git commit data using GPG-compatible signatures. Git's commit signing expects OpenPGP (RFC 4880) format signatures, which must be:

- **Detached Signatures**: Separate from commit data, embedded in commit object
- **ASCII Armored**: Base64-encoded with PGP headers for text-safe transport
- **Asymmetric Cryptography**: Private key signs, public key verifies (no shared secrets)
- **Algorithm Support**: RSA, EdDSA, ECDSA algorithms commonly used by Git

The service runs on Cloudflare Workers, which imposes constraints:

- **No Native GPG**: Workers don't support spawning GPG binary or accessing system keyring
- **Browser-Compatible Crypto**: Must use Web Crypto API or JavaScript implementations
- **Bundle Size**: Workers have 1MB compressed size limit (3MB uncompressed)
- **V8 Isolate Runtime**: No Node.js crypto module, filesystem, or external processes

Security requirements:

1. **Passphrase Protection**: Private keys encrypted at rest and in Durable Objects storage
2. **Memory Security**: Decrypted keys never persisted, cleared after signing operation
3. **Algorithm Safety**: Support modern algorithms (EdDSA, ECDSA), avoid deprecated (DSA, RSA-1024)
4. **Key Validation**: Parse and validate key format before storage

## Decision

Use **openpgp.js v6** as the cryptographic library with passphrase-encrypted private keys stored in Cloudflare Durable Objects.

### Library Selection: openpgp.js v6

**Why openpgp.js**:

- Full RFC 4880/4880bis (OpenPGP) implementation in JavaScript
- Works in Workers runtime (no Node.js dependencies)
- Uses Web Crypto API for cryptographic primitives (hardware-accelerated)
- Active maintenance, security audits, wide adoption (~1M npm downloads/week)
- Supports modern algorithms: EdDSA (Curve25519), ECDSA (P-256, P-384, P-521), RSA-2048/4096
- Detached signature generation with ASCII armor output

**Bundle Size**: ~300KB minified (well within 1MB Worker limit)

### Key Storage Architecture

**Encrypted Private Keys** (`src/utils/signing.ts:13-27`):

- Store ASCII-armored private keys encrypted with passphrase
- Passphrase stored as Cloudflare Worker secret (`KEY_PASSPHRASE`)
- Decrypt in-memory only during signing operation using `openpgp.decryptKey()`
- No plaintext keys in storage or logs

**Durable Object Storage** (`src/durable-objects/key-storage.ts`):

- Each key stored as JSON: `{ armoredPrivateKey, keyId, fingerprint, algorithm, createdAt }`
- Key ID as storage key: `key:${keyId}` for O(1) lookup
- Durable Objects provide globally consistent, strongly isolated storage
- SQLite-backed for free tier (unlimited read operations, 1000 writes/day)

**Key Metadata** (`src/schemas/keys.ts`, `src/utils/signing.ts:48-87`):

- Extract key ID, fingerprint, algorithm from private key on import
- Store metadata for audit logs and public key distribution
- Algorithm mapping follows RFC 4880 section 9.1 (RSA=1, EdDSA=22, ECDSA=19)
- Preserve user ID from key for display purposes

### Signing Operations

**Commit Data Signing** (`src/utils/signing.ts:13-46`):

```typescript
1. Read encrypted private key from Durable Object
2. Decrypt with passphrase (in-memory only)
3. Create OpenPGP message from commit data text
4. Generate detached signature with private key
5. Return ASCII-armored signature
6. Decrypted key cleared by garbage collection
```

**Performance**:

- Key decryption: ~20-50ms (depends on algorithm and passphrase iterations)
- Signature generation: ~5-15ms (EdDSA fastest, RSA slowest)
- Total signing latency: ~30-80ms end-to-end

**Signature Format** (`src/routes/sign.ts:178`):

- ASCII-armored detached signature (PGP SIGNATURE block)
- Compatible with `git verify-commit` and `git verify-tag`
- Returns raw signature text with `Content-Type: text/plain`

### Key Management

**Key Import** (`src/utils/signing.ts:48-87`):

- Parse ASCII-armored private key with `openpgp.readPrivateKey()`
- Validate passphrase by attempting decryption
- Extract metadata: key ID (16 hex chars), fingerprint (40 hex chars), algorithm name
- Reject keys that fail parsing or passphrase verification

**Public Key Export** (`src/utils/signing.ts:89-96`):

- Extract public key from private key using `toPublic().armor()`
- Return ASCII-armored public key for Git configuration
- Used by `/admin/public-key` endpoint for distribution
- Public key derivation is deterministic and always safe to expose

**Key Generation** (`scripts/generate-key.sh`):

- Generate keys offline using GPG CLI (not in Workers runtime)
- Store in `.keys/` directory (NOT `~/.gnupg`, isolated from user keyring)
- Export with passphrase encryption: `gpg --armor --export-secret-keys`
- Import to service via admin API

### Passphrase Handling

**Storage**:

- Passphrase stored as Cloudflare Worker secret (encrypted at rest by Cloudflare)
- Set via `wrangler secret put KEY_PASSPHRASE`
- Separate secrets for production and staging environments
- Never logged, never returned in API responses

**Usage**:

- Retrieved from `c.env.KEY_PASSPHRASE` only within signing handler
- Passed directly to `openpgp.decryptKey()`, never stored in variables
- No passphrase validation endpoint (prevents brute-force attacks)

**Rotation**:

- Passphrase change requires re-encrypting all stored keys
- No automated rotation (manual process)
- Consider re-keying instead of passphrase rotation for production

### Algorithm Support

**Supported Algorithms** (`src/utils/signing.ts:68-80`):

- **EdDSA** (Curve25519): Modern, fast, recommended for new keys
- **ECDSA** (P-256, P-384, P-521): Widely supported, good performance
- **RSA** (2048, 4096): Maximum compatibility, slower performance
- **DSA**: Supported for legacy keys, not recommended for new keys

**Unsupported Algorithms**:

- RSA-1024 (weak, considered broken)
- ElGamal (encryption-only, not for signing)

**Key Length Recommendations**:

- RSA: Minimum 2048-bit, recommend 4096-bit
- EdDSA: Curve25519 (fixed 256-bit)
- ECDSA: P-256 minimum, P-384 for high security

## Consequences

### Positive

**Git Compatibility**:

- Signatures work with all Git clients (no custom verification code)
- ASCII armor format identical to GPG output
- Supports all algorithms Git recognizes

**Worker-Native**:

- Pure JavaScript, no native binaries or external processes
- Fast cold-start times (~10ms, no GPG binary loading)
- Runs on Cloudflare's global edge network (low latency worldwide)

**Modern Cryptography**:

- Supports EdDSA (Curve25519), considered best practice for 2024+
- Web Crypto API acceleration for ECDSA and RSA operations
- Constant-time implementations prevent timing attacks

**Bundle Size**:

- openpgp.js ~300KB minified (30% of Worker limit)
- Room for additional dependencies and business logic
- Tree-shaking removes unused algorithm implementations

**Key Isolation**:

- Durable Objects provide strong isolation between keys
- Each key in separate namespace with access control
- Storage quota per Durable Object prevents DoS via storage exhaustion

### Negative

**Passphrase Single Point of Failure**:

- Compromise of `KEY_PASSPHRASE` secret exposes all stored private keys
- No per-key passphrase support (all keys use same passphrase)
- Passphrase rotation requires re-encrypting all keys

**No Hardware Security Module (HSM)**:

- Private keys exist in memory (V8 isolate) during signing
- No hardware-backed key storage (TPM, YubiKey, etc.)
- Cloudflare Workers don't support HSM integration

**Limited Key Management**:

- No automated key rotation
- No key expiration enforcement (must check manually)
- No revocation certificate handling

**JavaScript Crypto Performance**:

- 2-5x slower than native GPG for RSA operations
- EdDSA performance competitive with native (Web Crypto optimization)
- Memory usage higher than C implementations (~50MB heap during signing)

**No Streaming Signatures**:

- Entire commit data loaded into memory before signing
- Impractical for signing large objects (>10MB)
- Git commits typically <1MB, so not a practical limitation

### Security Considerations

**Attack Surface**:

- openpgp.js is pure JavaScript (no memory corruption vulnerabilities)
- Depends on Web Crypto API correctness (Cloudflare-maintained)
- Supply chain risk mitigated by npm integrity checksums and audit logs

**Side-Channel Resistance**:

- Web Crypto API implementations use constant-time operations
- openpgp.js designed to avoid timing attacks in high-level logic
- Workers runtime provides process isolation (separate V8 isolates per request)

**Memory Safety**:

- Decrypted keys cleared by garbage collection after signing
- No explicit memory zeroing (JavaScript limitation)
- V8 isolate destroyed after request completes (~50ms)

**Passphrase Security**:

- 10,000+ PBKDF2 iterations when keys generated by GPG (configurable)
- Cloudflare Worker secrets encrypted at rest (AES-256)
- Secrets never appear in logs or error messages

### Operational Considerations

**Key Generation Workflow**:

1. Generate key offline: `task generate:key` (uses GPG CLI in `.keys/` directory)
2. Export encrypted private key: `gpg --armor --export-secret-keys`
3. Import via admin API: `POST /admin/keys` with armored key and passphrase
4. Verify import: `GET /admin/keys` to list stored keys
5. Test signing: `POST /sign` with sample commit data

**Monitoring**:

- Track signing operation latency (alert if >200ms p99)
- Monitor key decryption failures (passphrase mismatch or corrupted key)
- Alert on key storage failures (Durable Object unavailability)

**Debugging**:

- Passphrase errors: "Failed to decrypt key" (check `KEY_PASSPHRASE` secret)
- Algorithm errors: "Unknown(N)" in metadata (unsupported algorithm)
- Signature verification failures: Check Git config matches public key fingerprint

**Backup and Recovery**:

- Export private keys via admin API: `GET /admin/keys` (requires admin token)
- Store encrypted backups offline (separate from service)
- Document passphrase separately from keys (split custody)

## Alternatives Considered

### Native GPG via WASM

- **Pros**: Exact GPG compatibility, proven implementation
- **Cons**: Large bundle size (>5MB), complex WASM build, no maintained GPG WASM port
- **Rejected**: Bundle size exceeds Worker limits, poor maintenance story

### Web Crypto API Only

- **Pros**: Minimal dependencies, hardware-accelerated
- **Cons**: No OpenPGP format support (raw ECDSA/RSA signatures), incompatible with Git
- **Rejected**: Git requires OpenPGP-formatted signatures, not raw crypto primitives

### node-forge

- **Pros**: Pure JavaScript, broad algorithm support
- **Cons**: Unmaintained, no EdDSA support, poor performance, large bundle size
- **Rejected**: Security concerns from lack of maintenance, inferior to openpgp.js

### TweetNaCl.js

- **Pros**: Small bundle (~7KB), fast EdDSA implementation
- **Cons**: No OpenPGP format, Ed25519 only, no RSA/ECDSA support
- **Rejected**: Git requires OpenPGP format, needs RSA for compatibility

### Cloudflare Workers KV for Key Storage

- **Pros**: Simpler API, global replication
- **Cons**: Eventually consistent (dangerous for key operations), no transactional updates
- **Rejected**: Strong consistency required for key storage, Durable Objects provide ACID guarantees

## References

- **OpenPGP.js Documentation**: https://openpgpjs.org/
- **RFC 4880 (OpenPGP)**: https://datatracker.ietf.org/doc/html/rfc4880
- **RFC 4880bis (OpenPGP Updates)**: https://datatracker.ietf.org/doc/html/draft-ietf-openpgp-rfc4880bis
- **Git Commit Signing**: https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work
- **Web Crypto API**: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
- **Implementation**: `/src/utils/signing.ts`, `/src/durable-objects/key-storage.ts`
