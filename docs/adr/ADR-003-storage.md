# ADR-003: Storage Architecture with Durable Objects, D1, and KV

## Status

Accepted

## Context

The GPG signing service requires storage for three distinct use cases, each with different consistency, latency, and durability requirements:

1. **Private Key Storage**: High-value secrets requiring strong consistency, isolation, and transactional semantics
2. **Audit Logs**: Write-heavy append-only log requiring queryable history and long-term retention
3. **JWKS Cache**: Low-value, high-read cache requiring global distribution and fast reads

The service runs on Cloudflare Workers, which provides multiple storage options:

- **Durable Objects**: Strongly consistent, globally unique coordination primitive with transactional storage
- **D1**: SQLite-based relational database with SQL queries and global replication
- **KV**: Eventually consistent key-value store with global edge caching
- **R2**: Object storage (not suitable for this use case - designed for large blobs)

Storage requirements:

- **Private Keys**: Strong consistency (no split-brain), sub-10ms read latency, ACID transactions, isolation between keys
- **Audit Logs**: Eventual consistency acceptable, SQL queries for filtering/reporting, infinite retention
- **JWKS Cache**: Eventual consistency acceptable, sub-5ms read latency, automatic TTL expiration, cache invalidation

## Decision

Use a **three-tier storage architecture** matching each data type to its optimal Cloudflare storage primitive:

### Tier 1: Durable Objects for Private Keys

**Why Durable Objects** (`src/durable-objects/key-storage.ts`):

- **Strong Consistency**: Single logical instance per key ID, no split-brain scenarios
- **Transactional Storage**: ACID guarantees for key create/update/delete operations
- **Isolation**: Each Durable Object is a separate V8 isolate with independent storage
- **Global Uniqueness**: Cloudflare routes all requests for a given key ID to the same Durable Object instance
- **SQLite Backend**: Free tier uses SQLite (unlimited reads, 1000 writes/day sufficient for key management)

**Storage Schema** (`src/durable-objects/key-storage.ts:81`):

```typescript
Storage Key: `key:${keyId}`
Value: {
  armoredPrivateKey: string,  // ASCII-armored encrypted private key
  keyId: string,              // 16 hex characters (RFC 4880)
  fingerprint: string,        // 40 hex characters (SHA-1 hash)
  algorithm: string,          // "RSA", "EdDSA", "ECDSA"
  createdAt: string           // ISO 8601 timestamp
}
```

**Access Patterns**:

- **Read Key** (`/get-key?keyId=X`): O(1) lookup by key ID, <10ms latency
- **Store Key** (`POST /store-key`): Transactional write, validates required fields
- **List Keys** (`/list-keys`): Scan with `prefix: "key:"`, returns metadata only (no private keys)
- **Delete Key** (`DELETE /delete-key?keyId=X`): Atomic deletion, returns whether key existed

**Binding Configuration** (`wrangler.toml:20-26`):

```toml
[[durable_objects.bindings]]
name = "KEY_STORAGE"
class_name = "KeyStorage"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["KeyStorage"]
```

**Routing Strategy** (`src/utils/durable-objects.ts:9-17`):

- Derive Durable Object ID from key ID hash (consistent routing)
- Single Durable Object can store multiple keys (namespace per key ID)
- Admin operations use "default" ID for service-wide key listing

### Tier 2: D1 for Audit Logs

**Why D1** (`src/utils/audit.ts`):

- **Relational Schema**: SQL queries for filtering by action, subject, date range
- **Write Scalability**: Designed for write-heavy workloads (append-only logs)
- **Global Replication**: Automatic replication to multiple regions
- **SQL Familiarity**: Standard SQL for reporting and analytics
- **Cost-Effective**: Free tier provides 5M rows reads/day, 100K writes/day

**Database Schema** (`migrations/0001_initial.sql`):

```sql
CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,           -- UUID v4
  timestamp TEXT NOT NULL,       -- ISO 8601
  request_id TEXT NOT NULL,      -- Request correlation ID
  action TEXT NOT NULL,          -- "sign", "store_key", "delete_key"
  issuer TEXT NOT NULL,          -- OIDC issuer URL
  subject TEXT NOT NULL,         -- OIDC subject (repository/project)
  key_id TEXT NOT NULL,          -- Key used for operation
  success INTEGER NOT NULL,      -- 1 = success, 0 = failure
  error_code TEXT,               -- Error code if failed
  metadata TEXT                  -- JSON additional context
);

CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_subject ON audit_logs(subject);
```

**Access Patterns**:

- **Write Log** (`src/utils/audit.ts:4-31`): Append-only INSERT, non-blocking via `ctx.waitUntil()`
- **Query Logs** (`src/utils/audit.ts:33-98`): Parameterized SELECT with filters (action, subject, date range)
- **Pagination**: LIMIT/OFFSET for large result sets (default 100 rows per page)
- **LIKE Injection Prevention**: Escape wildcards (`%`, `_`) before LIKE queries

**Binding Configuration** (`wrangler.toml:35-39`):

```toml
[[d1_databases]]
binding = "AUDIT_DB"
database_name = "gpg-signing-audit"
database_id = "46e29014-341c-47d1-adbb-e644ae28691c"
```

**Background Writes** (`src/routes/sign.ts:153-168`):

- Use `ctx.waitUntil()` to schedule audit logs asynchronously
- Response returned before log write completes (improves latency)
- Failures logged to console, don't block signing operation

### Tier 3: KV for JWKS Cache

**Why KV** (`src/middleware/oidc.ts:199-280`):

- **Global Edge Caching**: Cached JWKS served from nearest Cloudflare edge (sub-5ms)
- **Automatic TTL**: Keys expire after 5 minutes, automatic eviction
- **Eventually Consistent**: Acceptable for JWKS (stale cache triggers origin refresh)
- **High Read Throughput**: Unlimited reads on free tier, optimized for cache workloads

**Storage Schema**:

```typescript
Cache Key: `jwks:${issuer}`  // e.g., "jwks:https://token.actions.githubusercontent.com"
Value: {
  keys: [
    { kid: string, kty: string, use: string, alg: string, ... }
  ]
}
TTL: 300 seconds (5 minutes)
```

**Access Patterns**:

- **Read Cache** (`src/middleware/oidc.ts:207-219`): Check cache before fetching JWKS from origin
- **Cache Invalidation**: If requested `kid` not found, bypass cache and refresh from origin
- **Write Cache** (`src/middleware/oidc.ts:268-278`): Store JWKS after origin fetch, 5-minute TTL
- **Error Handling**: Cache write failures logged but don't fail request (cache is optimization)

**Binding Configuration** (`wrangler.toml:43-46`):

```toml
[[kv_namespaces]]
binding = "JWKS_CACHE"
id = "b4e1807f785b4b66b012004b14316d6a"
```

**Key Rotation Handling** (`src/middleware/oidc.ts:212-219`):

- Check if expected `kid` exists in cached JWKS
- If missing (new key rotated in), bypass cache and fetch from origin
- Prevents signature verification failures during OIDC provider key rotation

### Bonus: Durable Objects for Rate Limiting

**Why Durable Objects** (`src/durable-objects/rate-limiter.ts`):

- **Token Bucket Algorithm**: Track per-identity token consumption with refill
- **Strong Consistency**: Accurate rate limiting (no double-spending across edge)
- **Per-Identity Isolation**: Each OIDC identity gets separate Durable Object

**Storage Schema** (`src/durable-objects/rate-limiter.ts:9-12`):

```typescript
Storage Key: `bucket:${identity}`
Value: {
  tokens: number,      // Current token count (float for fractional refill)
  lastRefill: number   // Timestamp of last refill (ms since epoch)
}
```

**Rate Limit Configuration** (`src/durable-objects/rate-limiter.ts:18-20`):

- **Max Tokens**: 100 requests per window
- **Refill Rate**: 100 tokens per minute (1.67 tokens/second)
- **Window**: 60 seconds (rolling window, not fixed)

**Access Patterns**:

- **Check Limit** (`/check?identity=X`): Read token count without consuming
- **Consume Token** (`/consume?identity=X`): Atomic decrement if tokens >= 1
- **Reset Limit** (`POST /reset?identity=X`): Delete bucket (admin operation)

**Token Bucket Refill** (`src/durable-objects/rate-limiter.ts:123-142`):

- Calculate elapsed time since last refill
- Add tokens proportional to elapsed time: `(elapsed / windowMs) * refillRate`
- Cap at max tokens to prevent unbounded accumulation
- Update last refill timestamp on every access

## Consequences

### Positive

**Storage Type Safety**:

- Each data type stored in optimal primitive (consistency, latency, cost)
- No overloading of storage systems for inappropriate use cases
- Clear separation of concerns (secrets vs logs vs cache)

**Cost Efficiency**:

- Durable Objects SQLite backend: Free tier sufficient for key storage (low write volume)
- D1: Free tier covers 5M audit log reads/day, 100K writes/day
- KV: Unlimited reads on free tier, cache optimization reduces origin fetches

**Performance**:

- Private key reads: <10ms (Durable Object co-located with Worker)
- JWKS cache reads: <5ms (edge cache hit)
- Audit log writes: Non-blocking (background writes via `ctx.waitUntil()`)

**Consistency Guarantees**:

- Private keys: Strong consistency prevents split-brain key scenarios
- Rate limiting: Strong consistency prevents double-spending tokens
- Audit logs: Eventually consistent acceptable (append-only, no conflicts)
- JWKS cache: Eventually consistent acceptable (automatic invalidation on miss)

**Global Distribution**:

- Durable Objects: Automatically migrate to region with most requests
- D1: Global replication to multiple Cloudflare regions
- KV: Edge-cached in all 300+ Cloudflare data centers

**Operational Simplicity**:

- No external database dependencies (PostgreSQL, Redis, etc.)
- Cloudflare manages all storage infrastructure (no ops overhead)
- Unified billing and monitoring (Cloudflare dashboard)

### Negative

**Durable Objects Billing Complexity**:

- Free tier: 1000 writes/day per Durable Object
- Paid tier: $0.15/million requests + $0.20/GB-month storage
- Rate limiter high request volume may exceed free tier (each sign = 1 rate limit request)
- Unpredictable costs if request volume spikes

**D1 Query Limitations**:

- No full-text search (must use LIKE for text queries)
- No window functions in free tier (PARTITION BY, ROW_NUMBER)
- Query timeout: 30 seconds (sufficient for audit log queries)
- Max result set: 1MB per query (pagination required for large result sets)

**KV Eventual Consistency**:

- Cache writes may not be immediately visible globally (up to 60s propagation)
- Stale JWKS served if cache not yet updated after key rotation
- Mitigated by cache invalidation on `kid` mismatch, but 1-2 requests may fail

**No Cross-Storage Transactions**:

- Can't atomically update Durable Object + write D1 audit log
- Audit log write may fail while key operation succeeds (inconsistent audit trail)
- Mitigated by logging failures and retrying in background task

**Durable Object Cold Start**:

- First request to a Durable Object after idle: 50-200ms cold start
- Subsequent requests: <10ms (warm)
- Unpredictable latency for infrequently used keys

**D1 Write Latency**:

- Write latency: 20-50ms (replication to multiple regions)
- Non-blocking writes via `ctx.waitUntil()` hide latency from user
- Increased Worker CPU time billed (background task execution)

### Operational Considerations

**Database Migrations**:

- D1 migrations: `task db:migrate` (applies `.sql` files in `migrations/`)
- Durable Objects migrations: `wrangler.toml` `[[migrations]]` block
- No automated rollback (must manually revert migrations)

**Backup and Recovery**:

- Durable Objects: Export via admin API (`GET /admin/keys`)
- D1: Export via `wrangler d1 export` (SQLite dump)
- KV: No backup needed (cache, can be rebuilt from origin)

**Monitoring**:

- Durable Objects: Request count, duration, storage size per object
- D1: Query count, duration, row count, database size
- KV: Read/write throughput, cache hit rate, storage size

**Quotas and Limits** (Free Tier):

- Durable Objects: 1000 writes/day per object
- D1: 5M reads/day, 100K writes/day, 5GB storage
- KV: Unlimited reads, 1000 writes/day, 1GB storage

**Debugging**:

- Durable Object errors: Check Cloudflare Workers logs (tail logs via `wrangler tail`)
- D1 errors: Query via `wrangler d1 execute` for manual inspection
- KV errors: List keys via `wrangler kv:key list` to inspect cache state

**Environment Isolation** (`wrangler.toml:73-106`):

- Separate storage instances for staging and production
- Staging uses different database IDs and KV namespace IDs
- Prevents accidental production data access from staging

## Alternatives Considered

### External PostgreSQL Database

- **Pros**: Full SQL feature set, mature ecosystem, better query performance
- **Cons**: External dependency, latency from Workers to DB (50-200ms), requires VPC/Argo Tunnel, operational overhead
- **Rejected**: Added complexity and latency outweighs benefits, D1 sufficient for current scale

### KV for Private Keys

- **Pros**: Simple API, fast reads, global distribution
- **Cons**: Eventually consistent (dangerous for keys), no transactions, no isolation
- **Rejected**: Strong consistency required for private keys, eventual consistency unacceptable

### Durable Objects for Audit Logs

- **Pros**: Strong consistency, fast writes
- **Cons**: No SQL queries, expensive for high write volume, limited to 1 Durable Object per key
- **Rejected**: Need SQL for audit log queries, write volume exceeds Durable Object cost efficiency

### R2 for Audit Logs

- **Pros**: Cheap storage ($0.015/GB-month), large object support
- **Cons**: No queries (must download and parse), high latency (50-200ms), designed for blobs not logs
- **Rejected**: Need query capability, latency unacceptable for real-time audit

### Redis/Memcached for JWKS Cache

- **Pros**: Rich data structures, atomic operations, familiar API
- **Cons**: External dependency, latency from Workers, operational overhead, cost
- **Rejected**: KV provides equivalent caching with zero ops, better integration

### Single Storage Type (D1 for Everything)

- **Pros**: Simplicity, single storage system
- **Cons**: D1 not designed for private keys (no isolation), poor cache latency
- **Rejected**: Security concerns for private keys, performance concerns for cache

## References

- **Durable Objects**: https://developers.cloudflare.com/durable-objects/
- **D1 Database**: https://developers.cloudflare.com/d1/
- **Workers KV**: https://developers.cloudflare.com/kv/
- **Workers Limits**: https://developers.cloudflare.com/workers/platform/limits/
- **Implementation**:
  - Key Storage: `/src/durable-objects/key-storage.ts`
  - Rate Limiter: `/src/durable-objects/rate-limiter.ts`
  - Audit Logs: `/src/utils/audit.ts`
  - JWKS Cache: `/src/middleware/oidc.ts` (lines 199-280)
