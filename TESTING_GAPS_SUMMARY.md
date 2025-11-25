# GPG Signing Service - Testing Gaps Quick Reference

**Last Updated**: 2025-11-25
**Overall Coverage**: 93.6% (799/854 statements)
**Status**: Good foundation, critical security gaps

---

## 🔴 CRITICAL - Must Fix Immediately

### C1: Timing Attack on Admin Token

- **File**: `src/middleware/oidc.ts` line 72-89
- **Function**: `timingSafeEqual()`
- **Gap**: NO TESTS for timing attack resistance
- **Risk**: Enables brute-force token enumeration
- **Fix**: Create `src/__tests__/timing-attack.test.ts`
- **Time**: 1-2 hours
- **Priority**: 1 (Security)

### C2: SSRF in JWKS Fetching

- **File**: `src/middleware/oidc.ts` line 187-241
- **Function**: `getJWKS()`
- **Gap**: NO TESTS for internal IP, HTTPS, redirect loops
- **Risk**: Could leak OIDC credentials to internal services
- **Fix**: Add 5+ tests to `src/__tests__/middleware.test.ts`
- **Time**: 2-3 hours
- **Priority**: 2 (Security)

### C3: Database Utils - 0% Coverage

- **File**: `src/utils/database.ts`
- **Gap**: 25 UNTESTED statements (100% missing)
- **Functions**: `transformAuditLogRow()`, `D1QueryBuilder` class
- **Risk**: Audit logging completely untested
- **Fix**: Create `src/__tests__/database.test.ts` with 8 tests
- **Time**: 2 hours
- **Priority**: 3 (Functionality)

### C4: Error Handling - 0% Coverage

- **File**: `src/utils/errors.ts`
- **Gap**: 13 UNTESTED statements (100% missing)
- **Functions**: `errorResponse()`, `handleUnknownError()`, `AppError` class
- **Risk**: Error responses never validated
- **Fix**: Create `src/__tests__/errors.test.ts` with 6 tests
- **Time**: 1.5 hours
- **Priority**: 4 (Functionality)

---

## 🟡 HIGH - Complete Soon

### H1: Logger - 47.6% Coverage

- **File**: `src/utils/logger.ts`
- **Gap**: 11 untested statements
- **Missing**: Log level filtering, context formatting, stack traces
- **Fix**: Create `src/__tests__/logger.test.ts` with 8 tests
- **Time**: 1.5 hours
- **Effort**: Low

### H2: Branded Types - 71.4% Coverage

- **File**: `src/types/branded.ts`
- **Gap**: 4 untested statements
- **Missing**: Format validation, edge cases
- **Fix**: Create `src/__tests__/types.test.ts` with 3 tests
- **Time**: 1 hour
- **Effort**: Low

### H3: CLI Tool - No Tests

- **File**: `client/cmd/gpg-sign/main.go`
- **Gap**: 0 tests, full file untested
- **Missing**: Argument parsing, file I/O, exit codes
- **Fix**: Create `client/cmd/gpg-sign/main_test.go` with 6 tests
- **Time**: 2 hours
- **Effort**: Medium

### H4: Input Validation Boundaries

- **Gap**: KeyId length limits, hex validation, size limits
- **Fix**: Add 4 tests to validation suite
- **Time**: 1 hour
- **Effort**: Low

---

## 🟢 MEDIUM - Schedule Soon

### M1: Crypto Failure Modes

- **Missing**: Key corruption, timeout, partial decryption
- **Tests**: 3 tests in `src/__tests__/signing.test.ts`
- **Time**: 1 hour
- **Impact**: Error handling confidence

### M2: Performance Testing

- **Missing**: Load testing, latency benchmarks, memory profiling
- **Setup**: Vitest benchmarks
- **Time**: 8+ hours
- **Impact**: Operational readiness

### M3: Coverage Report Details

| File                            | Coverage | Statements | Status       |
| ------------------------------- | -------- | ---------- | ------------ |
| **CRITICAL GAPS**               |          |            |              |
| utils/database.ts               | 0%       | 0/25 ⚠️     | Never tested |
| utils/errors.ts                 | 0%       | 0/13 ⚠️     | Never tested |
| utils/logger.ts                 | 47.6%    | 10/21 ⚠️    | Partial      |
| types/branded.ts                | 71.4%    | 10/14 ⚠️    | Partial      |
| **EXCELLENT**                   |          |            |              |
| index.ts                        | 100%     | 44/44 ✅   | Complete     |
| durable-objects/key-storage.ts  | 100%     | 35/35 ✅   | Complete     |
| durable-objects/rate-limiter.ts | 100%     | 43/43 ✅   | Complete     |
| middleware/oidc.ts              | 100%     | 93/93 ✅   | Complete     |
| middleware/security.ts          | 100%     | 43/43 ✅   | Complete     |
| routes/sign.ts                  | 100%     | 42/42 ✅   | Complete     |
| routes/admin.ts                 | 98.6%    | 73/74 ✅   | Near-perfect |

---

## 📊 Test Status by Category

### Security Testing

| Item                   | Status                    | Notes                           |
| ---------------------- | ------------------------- | ------------------------------- |
| OIDC validation        | ✅ Tested                 | 26 tests                        |
| Rate limiting          | ✅ Tested                 | 41 tests                        |
| Admin token comparison | ⚠️ **Untested for timing** | NO timing tests                 |
| SSRF prevention        | ⚠️ **Partially tested**    | NO protocol/IP validation tests |
| Input validation       | ✅ Tested                 | 109 schema tests                |

### Functionality Testing

| Module              | Tests | Coverage    |
| ------------------- | ----- | ----------- |
| Routes (sign/admin) | 26    | 100% ✅     |
| Middleware          | 73    | 100% ✅     |
| Durable Objects     | 49    | 100% ✅     |
| Database utilities  | 0     | **0% ⚠️**    |
| Error handling      | 0     | **0% ⚠️**    |
| Logging             | ~5    | **47.6% ⚠️** |
| Types               | ~3    | **71.4% ⚠️** |

### Integration Testing

| Component     | Tests | Status        |
| ------------- | ----- | ------------- |
| E2E API flow  | 41    | ✅ Complete   |
| OIDC + JWKS   | 26    | ✅ Complete   |
| Rate limiting | 41    | ✅ Complete   |
| Key storage   | 35    | ✅ Complete   |
| Audit logging | 12    | ✅ Complete   |
| **CLI tool**  | **0** | **⚠️ Missing** |

### Go Client (Separate - 88.9% coverage)

| Component       | Coverage | Status        |
| --------------- | -------- | ------------- |
| Client creation | 100%     | ✅            |
| Retry logic     | 100%     | ✅            |
| Error handling  | 100%     | ✅            |
| All API methods | 100%     | ✅            |
| **CLI tool**    | **0%**   | **⚠️ Missing** |

---

## 🚀 Implementation Priority

### Week 1 (Critical - 8-10 hours)

1. **Timing attack tests** (C1) - 1-2h - START HERE
2. **SSRF tests** (C2) - 2-3h
3. **Database tests** (C3) - 2h
4. **Error tests** (C4) - 1.5h
5. **Logger tests** (H1) - 1.5h

**Target**: 97%+ coverage, 0 security gaps

### Week 2 (High Priority - 5-6 hours)

1. **Branded types tests** (H2) - 1h
2. **CLI tool tests** (H3) - 2h
3. **Input validation** - 1h
4. **Crypto failure modes** - 1h

**Target**: 98%+ coverage, all critical paths

### Week 3-4 (Performance)

1. Load testing benchmarks
2. Latency profiling
3. Memory profiling

**Target**: Performance baselines established

---

## 📋 Specific Test Files to Create

### PHASE 1 (Week 1)

```bash
src/__tests__/
├── timing-attack.test.ts       NEW - Timing attack resistance (C1)
├── database.test.ts             NEW - D1 utilities (C3)
├── errors.test.ts               NEW - Error handling (C4)
├── logger.test.ts               NEW - Logger impl (H1)
└── middleware.test.ts           MODIFY - Add SSRF tests (C2)
```

### PHASE 2 (Week 2)

```bash
src/__tests__/
├── types.test.ts                NEW - Branded types (H2)
└── validation.test.ts           NEW - Input boundaries
client/cmd/gpg-sign/
└── main_test.go                 NEW - CLI tool (H3)
```

### PHASE 3 (Week 3-4)

```bash
src/__tests__/perf/
├── load.bench.ts                NEW - Concurrent requests
├── oidc.bench.ts                NEW - Token validation
├── database.bench.ts            NEW - D1 queries
└── rate-limit.bench.ts          NEW - Rate limiter throughput
```

---

## 🎯 Success Metrics

**After Phase 1**:

- [x] Coverage: 97%+ (up from 93.6%)
- [x] Security: Timing attack & SSRF tests added
- [x] Database: 100% coverage (was 0%)
- [x] Errors: 100% coverage (was 0%)
- [x] Logger: 90%+ coverage (was 47.6%)
- [ ] Tests: 226 → 250+
- [ ] CI Pass Rate: 100%

**After Phase 2**:

- [x] Coverage: 98%+ (up from 97%)
- [x] CLI: Tested (was 0 tests)
- [x] All utilities: 95%+ coverage
- [ ] Tests: 250+ → 265+

**After Phase 3**:

- [x] Performance baselines established
- [x] Load testing framework in place
- [x] SLO targets defined

---

## 🔗 Related Documents

- **TEST_EVALUATION_REPORT.md** - Full analysis with details
- **TESTING_ACTION_PLAN.md** - Implementation guide with code examples
- **Coverage Report** - `coverage/index.html` (HTML coverage visualization)

---

## ⚡ Quick Start

### Run Current Tests

```bash
bun run test              # All tests (226 tests, ~9.6s)
bun run test:coverage    # With coverage report
```

### After Implementing Phase 1

```bash
bun run test:coverage    # Should show 97%+ coverage
bun run test -- timing-attack
bun run test -- database
bun run test -- errors
bun run test -- logger
bun run test -- middleware (check SSRF tests)
```

### Expected Coverage Progression

```
Current:  93.6% (799/854)
Phase 1:  97.0% (827/854)  [+28 statements, -28 gaps]
Phase 2:  98.0% (836/854)  [+9 statements, -9 gaps]
Target:   98.5% (839/854)  [+3 statements, -3 gaps]
```

---

## 📝 Notes

- All tests follow existing patterns in `src/__tests__/`
- Use existing test helpers (createMockContext, etc.)
- Each test should be independent (no shared state)
- Mock external dependencies (fetch, D1, KV)
- Document any new patterns or utilities created

---

**Status Dashboard**:

- [x] Analysis complete
- [x] Gaps identified
- [x] Priority matrix established
- [ ] Phase 1 implementation (in progress)
- [ ] Phase 2 implementation (pending)
- [ ] Phase 3 implementation (pending)
- [ ] Coverage target: 98%+ (pending)

---

**Time Estimate to Excellence**: 25-30 hours

- Phase 1 (Critical): 8-10 hours
- Phase 2 (High): 5-6 hours
- Phase 3 (Performance): 8+ hours
