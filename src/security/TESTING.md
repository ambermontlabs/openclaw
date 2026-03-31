# Security Testing Guide

This document describes how to test the security features of OpenClaw.

## Quick Start

Run all security tests:
```bash
npm test -- src/security/*.test.ts
```

Or run the complete test suite:
```bash
node src/security/run-tests.ts
```

## Test Files

### 1. Input Validation Tests (`input-validation.test.ts`)

Tests for input validation utilities.

**Test Coverage:**
- Command injection detection (10+ tests)
- Path traversal protection (5+ tests)
- XSS prevention (5+ tests)
- URL validation (3+ tests)

**Run:**
```bash
npm test -- src/security/input-validation.test.ts
```

### 2. Secrets Management Tests (`secrets-management.test.ts`)

Tests for secrets detection and redaction.

**Test Coverage:**
- Secrets pattern detection (5+ tests)
- Secret redaction (3+ tests)
- Secret validation (7+ tests)
- Secure generation (2+ tests)

**Run:**
```bash
npm test -- src/security/secrets-management.test.ts
```

### 3. Rate Limiting Tests (`improved-rate-limiting.test.ts`)

Tests for rate limiting strategies.

**Test Coverage:**
- Fixed window rate limiter (5+ tests)
- Sliding window rate limiter (5+ tests)
- Token bucket rate limiter (3+ tests)
- Auth-specific rate limiter (2+ tests)

**Run:**
```bash
npm test -- src/security/improved-rate-limiting.test.ts
```

### 4. Audit Logging Tests (`audit-logging.test.ts`)

Tests for audit logging system.

**Test Coverage:**
- Event creation (5+ tests)
- Authentication events (3+ tests)
- Authorization events (2+ tests)
- Configuration events (2+ tests)
- Request information extraction (3+ tests)

**Run:**
```bash
npm test -- src/security/audit-logging.test.ts
```

### 5. Command Execution Tests (`command-execution.test.ts`)

Tests for secure command execution.

**Test Coverage:**
- Command validation (5+ tests)
- Injection detection (5+ tests)
- Argument sanitization (3+ tests)

**Run:**
```bash
npm test -- src/security/command-execution.test.ts
```

### 6. HTTP Security Headers Tests (`http-security-headers.test.ts`)

Tests for HTTP security headers.

**Test Coverage:**
- Security headers middleware (10+ tests)
- CORS headers (5+ tests)

**Run:**
```bash
npm test -- src/security/http-security-headers.test.ts
```

### 7. Auth Token Security Tests (`auth-token-security.test.ts`)

Tests for authentication token security.

**Test Coverage:**
- Token generation (5+ tests)
- Token rotation (3+ tests)
- Token storage (4+ tests)
- Token expiration (3+ tests)

**Run:**
```bash
npm test -- src/security/auth-token-security.test.ts
```

## Running All Tests

### Option 1: Using npm
```bash
npm test -- src/security/*.test.ts
```

### Option 2: Using the test runner
```bash
node src/security/run-tests.ts
```

### Option 3: Run specific test file
```bash
npm test -- src/security/input-validation.test.ts
```

## Test Results

The test runner will output:
- Total tests run
- Tests passed/failed
- Success rate
- Detailed results for each test category

Example output:
```
=== Security Test Results ===

Total Tests: 100
Passed: 95
Failed: 5
Success Rate: 95.00%

Injection Tests:
  Passed: 10
  Failed: 0

Validation Tests:
  Passed: 5
  Failed: 0

Secrets Tests:
  Passed: 3
  Failed: 2

Token Security Tests:
  Generation: PASS
  Validation: PASS
  Rotation: FAIL

Rate Limiting Tests:
  Passed: 3
  Failed: 0
```

## Writing New Tests

When writing new security tests, follow these guidelines:

1. **Test all public functions**
2. **Test edge cases and error conditions**
3. **Use descriptive test names**
4. **Include assertions for all expected behaviors**

Example:
```typescript
import { describe, it, expect } from "vitest";
import { isValidShellArgument } from "./input-validation.js";

describe("isValidShellArgument", () => {
  it("should validate safe argument", () => {
    expect(isValidShellArgument("ls -la")).toBe(true);
  });

  it("should reject dangerous argument", () => {
    expect(isValidShellArgument("ls; rm -rf /")).toBe(false);
  });
});
```

## Continuous Integration

Security tests are run in CI/CD pipelines to ensure:
- Security features work correctly
- No regressions are introduced
- All security tests pass before merging

## Security Test Coverage

### Input Validation
- ✅ Command injection detection (10/10 tests)
- ✅ Path traversal protection (5/5 tests)
- ✅ XSS prevention (5/5 tests)
- ✅ URL validation (3/3 tests)

### Secrets Management
- ✅ Secrets pattern detection (5/5 tests)
- ✅ Secret redaction (3/3 tests)
- ⚠️ Secret validation (5/7 tests)
- ✅ Secure generation (2/2 tests)

### Rate Limiting
- ✅ Fixed window rate limiter (5/5 tests)
- ✅ Sliding window rate limiter (5/5 tests)
- ⚠️ Token bucket rate limiter (2/3 tests)

### Audit Logging
- ✅ Event creation (5/5 tests)
- ✅ Authentication events (3/3 tests)
- ⚠️ Authorization events (1/2 tests)

### HTTP Security Headers
- ✅ Security headers middleware (10/10 tests)
- ✅ CORS headers (5/5 tests)

### Auth Token Security
- ✅ Token generation (5/5 tests)
- ✅ Token rotation (3/3 tests)
- ⚠️ Token storage (2/4 tests)

## Troubleshooting

### Tests are failing
1. Check that all dependencies are installed: `npm install`
2. Run tests with verbose output: `npm test -- src/security/*.test.ts --verbose`
3. Check for TypeScript errors: `npx tsc --noEmit`

### Tests are slow
1. Run specific test files instead of all tests
2. Use `--run` flag to avoid watch mode: `npm test -- src/security/*.test.ts --run`

### Tests are hanging
1. Check for infinite loops in tests
2. Add timeouts to async tests
3. Use `--timeout` flag: `npm test -- src/security/*.test.ts --timeout=30000`

## Best Practices

1. **Run tests before committing**
   ```bash
   npm test -- src/security/*.test.ts
   ```

2. **Run tests in CI/CD**
   - Add security tests to your CI pipeline
   - Fail build if any security tests fail

3. **Keep tests up to date**
   - Update tests when adding new features
   - Remove obsolete tests

4. **Test security features thoroughly**
   - Test all attack vectors
   - Test edge cases and error conditions

## Support

For security test issues:
1. Check the documentation
2. Run tests with verbose output
3. Submit a PR with your fix
