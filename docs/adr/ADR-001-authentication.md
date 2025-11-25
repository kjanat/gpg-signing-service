# ADR-001: OIDC Authentication for CI/CD Environments

## Status

Accepted

## Context

The GPG signing service needs to authenticate API requests from automated CI/CD pipelines (GitHub Actions, GitLab CI) running in distributed, ephemeral environments. Traditional authentication approaches face challenges:

- **Static API Keys**: Difficult to rotate, must be stored as secrets, high blast radius if compromised
- **User Credentials**: Inappropriate for automated workflows, require manual intervention
- **Mutual TLS**: Complex certificate management, difficult to provision in ephemeral environments
- **Basic Auth**: No standardized identity claims, weak security model

CI/CD platforms provide native OIDC token provisioning that addresses these challenges:

- **GitHub Actions**: Issues JWT tokens via `ACTIONS_ID_TOKEN_REQUEST_URL` with repository, workflow, and ref claims
- **GitLab CI**: Provides JWT tokens through `CI_JOB_JWT` with project, pipeline, and namespace claims
- **Ephemeral by Design**: Tokens are short-lived (typically 5-10 minutes), automatically rotated per job
- **Rich Claims**: Include context about repository, workflow, branch, and environment
- **Zero Secret Management**: No credentials to store or rotate

The service requires:

1. Strong authentication without manual secret distribution
2. Audit trail linking signatures to specific repositories/workflows
3. Support for multiple CI/CD platforms with minimal configuration
4. Protection against common attacks (token replay, SSRF, timing attacks)

## Decision

Implement OIDC (OpenID Connect) JWT validation as the primary authentication mechanism with:

### Token Validation Pipeline

**Algorithm Whitelist** (`src/middleware/oidc.ts:93-94`):

- Allow only asymmetric algorithms: `RS256`, `RS384`, `RS512`, `ES256`, `ES384`
- Reject symmetric algorithms (HS256) that enable key confusion attacks
- Validate algorithm claim before JWKS fetch to prevent SSRF amplification

**Issuer Validation**:

- Whitelist trusted issuers via `ALLOWED_ISSUERS` environment variable
- Default: `https://token.actions.githubusercontent.com,https://gitlab.com`
- Issuer checked before JWKS retrieval to limit attack surface

**Temporal Claims** (`src/middleware/oidc.ts:124-135`):

- 60-second clock skew tolerance for `nbf` (not-before) and `exp` (expiration)
- Prevents legitimate failures due to clock drift across distributed systems
- Tight enough to limit replay window for compromised tokens

**Audience Validation** (`src/middleware/oidc.ts:138-142`):

- Configurable via `EXPECTED_AUDIENCE` (defaults to "gpg-signing-service")
- Supports array or string audience claims
- Prevents token reuse across different services

**Signature Verification** (`src/middleware/oidc.ts:162-184`):

- Fetch JWKS from issuer's `.well-known/openid-configuration` endpoint
- Use `jose` library for cryptographic verification with `createLocalJWKSet`
- Pre-flight validation: Check key exists and `use: "sig"` before verification
- Prevents unhandled rejections from missing keys in JWKS

### Security Hardening

**SSRF Protection** (`src/middleware/oidc.ts:225-257`):

- Validate all OIDC URLs (well-known config, JWKS URI) before fetching
- Block private IP ranges, localhost, metadata endpoints via `validateUrl()`
- Prevents attackers from using issuer field to probe internal networks

**JWKS Caching** (`src/middleware/oidc.ts:199-220`):

- Cache JWKS for 5 minutes in Cloudflare KV (`JWKS_CACHE`)
- Automatic cache invalidation if requested `kid` (key ID) not found
- Handles key rotation: Refresh from origin when new key appears
- 10-second timeout on JWKS fetches to prevent hanging requests

**Timing Attack Mitigation** (`src/middleware/oidc.ts:73-90`):

- Admin token comparison uses `crypto.subtle.timingSafeEqual`
- Pad strings to equal length before comparison
- Prevents attackers from brute-forcing admin tokens through timing measurements

### Identity Extraction

**Validated Claims** (`src/types/oidc.ts:52-66`):

- Marker interface `ValidatedOIDCClaims` with `__validated: true` flag
- Type-level proof that claims passed verification
- Prevents accidental use of unvalidated claims in downstream handlers

**Identity Mapping** (`src/middleware/oidc.ts:35`):

- Create identity from `iss` (issuer) + `sub` (subject) for rate limiting
- Store validated claims in Hono context for audit logging
- Preserve platform-specific fields: `repository`, `workflow` (GitHub), `project_path`, `pipeline_source` (GitLab)

### Admin Endpoints

**Dual Authentication** (`src/middleware/oidc.ts:45-70`):

- Admin endpoints (`/admin/*`) use Bearer token authentication
- Static token stored as Cloudflare Worker secret (`ADMIN_TOKEN`)
- Constant-time comparison prevents timing attacks
- Separate from OIDC to support manual key management operations

## Consequences

### Positive

**Zero Secret Distribution**:

- No API keys to distribute or rotate manually
- CI/CD platforms handle token lifecycle automatically
- Tokens expire after 5-10 minutes, limiting compromise window

**Strong Identity Binding**:

- Audit logs capture exact repository, workflow, branch, and commit SHA
- Each signature traceable to specific CI/CD job run
- Supports compliance and forensic investigations

**Multi-Platform Support**:

- Works with GitHub Actions and GitLab CI out-of-box
- Easy to add new OIDC providers (update `ALLOWED_ISSUERS`)
- Standardized protocol reduces custom integration code

**Cloudflare-Native Caching**:

- KV-backed JWKS cache reduces latency (5ms vs 100ms HTTPS fetch)
- Global edge distribution of cached keys
- Automatic eviction based on TTL and cache pressure

**Attack Surface Reduction**:

- SSRF protection prevents issuer-based network probing
- Algorithm whitelist blocks key confusion attacks
- Timing-safe comparison prevents admin token leakage

### Negative

**CI/CD Platform Dependency**:

- Requires GitHub Actions or GitLab CI OIDC token provisioning
- Manual testing requires token generation outside CI/CD
- Users must configure `id-token: write` permission in workflows

**Network Dependency**:

- JWKS fetch requires outbound HTTPS to issuer (blocked if issuer unavailable)
- Cache miss during key rotation adds 100-200ms latency
- No offline operation mode

**Clock Skew Sensitivity**:

- 60-second skew tolerance may be insufficient for severely drifted clocks
- Workers run in Cloudflare's edge network (generally accurate), but issuers may drift
- Failures manifest as "Token expired" or "Token not yet valid" errors

**Admin Token Management**:

- Static admin token requires manual rotation via `wrangler secret put`
- No automated rotation or expiration
- Compromise requires manual intervention and secret update

**Key Rotation Handling**:

- Cache invalidation on `kid` mismatch adds network fetch latency
- Short cache TTL (5 minutes) increases JWKS fetch frequency
- No pre-warming of new keys before rotation

### Operational Considerations

**Setup Complexity**:

- Users must configure OIDC token provisioning in CI/CD workflows
- GitHub Actions: Add `id-token: write` permission to job
- GitLab CI: Token automatically available as `CI_JOB_JWT`
- Documentation required for audience claim configuration

**Monitoring**:

- Track JWKS cache hit rate to optimize TTL
- Alert on SSRF protection triggers (potential attack)
- Monitor admin token usage patterns (detect abuse)
- Log signature verification failures for debugging

**Debugging**:

- Token expiration errors common when workflows take >10 minutes
- Audience mismatch errors if service name changes
- Issuer whitelist errors require environment variable update
- JWKS fetch failures may indicate network issues or issuer outage

## Alternatives Considered

### API Key Authentication

- **Pros**: Simple, no external dependencies, works offline
- **Cons**: Manual rotation, storage in CI/CD secrets, high blast radius, no identity claims
- **Rejected**: Poor security model for automated systems, difficult operational overhead

### Mutual TLS (mTLS)

- **Pros**: Strong cryptographic identity, no token parsing
- **Cons**: Complex certificate lifecycle, difficult to provision in ephemeral environments, no built-in CI/CD support
- **Rejected**: Operational complexity outweighs security benefits for this use case

### GitHub App Installation Tokens

- **Pros**: Native GitHub integration, fine-grained permissions
- **Cons**: GitHub-specific, requires app installation per org, no GitLab support
- **Rejected**: Vendor lock-in, doesn't support multi-platform requirements

### Signed URL with HMAC

- **Pros**: Simple, no external validation
- **Cons**: Shared secret required, no standard protocol, poor identity claims
- **Rejected**: Reinventing OIDC with worse security properties

## References

- **OIDC Spec**: https://openid.net/specs/openid-connect-core-1_0.html
- **GitHub Actions OIDC**: https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect
- **GitLab CI JWT**: https://docs.gitlab.com/ee/ci/secrets/id_token_authentication.html
- **RFC 7519 (JWT)**: https://datatracker.ietf.org/doc/html/rfc7519
- **RFC 7517 (JWKS)**: https://datatracker.ietf.org/doc/html/rfc7517
- **Implementation**: `/src/middleware/oidc.ts`, `/src/types/oidc.ts`
