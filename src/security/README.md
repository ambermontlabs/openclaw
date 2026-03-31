# OpenClaw Security Module

This directory contains comprehensive security utilities for the OpenClaw platform.

## Overview

The security module provides protection against common attack vectors including:

- **Injection Attacks**: Command, path traversal, XSS, SQL injection
- **Secrets Leakage**: Automatic detection and redaction
- **Authentication**: Token security, rotation, expiration
- **Rate Limiting**: Multiple strategies with middleware
- **HTTP Security**: Headers and CORS
- **Audit Logging**: Structured security event logging

## Quick Start

```typescript
import { 
  isValidShellArgument,
  escapeHtml,
  redactSecrets,
  AuditLogger,
  createAuthRateLimiter
} from "@openclaw/security";

// Validate input
if (!isValidShellArgument(userInput)) {
  throw new Error("Invalid input");
}

// Escape HTML
const safeHtml = escapeHtml(userInput);

// Sanitize logs
const safeLog = redactSecrets(logMessage);

// Audit logging
const logger = new AuditLogger("gateway");
logger.logAuthentication(userId, success);

// Rate limiting
const limiter = createAuthRateLimiter();
if (!limiter.check(key).allowed) {
  throw new Error("Too many attempts");
}
```

## Available Modules

### 1. Input Validation (`input-validation.ts`)

Comprehensive input validation utilities.

**Key Functions:**
- `containsDangerousShellChars()` - Detect command injection
- `isValidPath()` - Prevent path traversal
- `escapeHtml()` - Prevent XSS
- `containsSqlInjection()` - Detect SQL injection
- `isValidInteger()` - Validate integers with bounds
- `safeParseJson()` - Prevent JSON DoS

### 2. Command Execution (`command-execution.ts`)

Secure command execution with validation.

**Key Functions:**
- `validateCommand()` - Validate before execution
- `safeExec()` - Execute safely
- `sanitizeCommand()` - Sanitize input

### 3. Secrets Management (`secrets-management.ts`)

Secrets detection and redaction.

**Key Functions:**
- `containsSecrets()` - Detect secrets
- `redactSecrets()` - Redact from strings
- `sanitizeLogMessage()` - Sanitize logs
- `validateSecret()` - Validate security requirements
- `generateSecureSecret()` - Generate secure secrets

### 4. HTTP Security Headers (`http-security-headers.ts`)

HTTP security headers middleware.

**Features:**
- Content-Security-Policy
- X-Content-Type-Options, X-Frame-Options, etc.
- CORS security

### 5. Audit Logging (`audit-logging.ts`)

Structured audit logging.

**Key Classes:**
- `AuditLogger` - Log security events
  - `logAuthentication()`
  - `logAuthorization()`
  - `logConfiguration()`
  - `logFileAccess()`
  - `logCommandExecution()`

### 6. Authentication Token Security (`auth-token-security.ts`)

Token security and management.

**Key Classes:**
- `TokenRotationManager` - Token rotation
- `SecureTokenStorage` - Secure storage
- `TokenExpirationManager` - Expiration management

### 7. Rate Limiting (`improved-rate-limiting.ts`)

Multiple rate limiting strategies.

**Key Classes:**
- `FixedWindowRateLimiter`
- `SlidingWindowRateLimiter` (default)
- `TokenBucketRateLimiter`
- `createAuthRateLimiter()` - Auth-specific
- `createApiRateLimiter()` - API-specific

### 8. Security Testing (`testing.ts`)

Security testing utilities.

**Key Functions:**
- `runSecurityTestSuite()` - Run all tests
- `printTestResults()` - Print results
- `generateInjectionTests()` - Generate injection tests

## Security Best Practices

### 1. Input Validation
```typescript
import { isValidShellArgument, escapeHtml } from "@openclaw/security";

// Always validate user input
if (!isValidShellArgument(input)) {
  throw new Error("Invalid input");
}

// Always escape HTML
const safeHtml = escapeHtml(userInput);
```

### 2. Secrets Management
```typescript
import { sanitizeLogMessage, redactSecrets } from "@openclaw/security";

// Never log secrets directly
const safeMessage = sanitizeLogMessage(messageWithSecrets);
console.log(safeMessage);

// Redact secrets from logs
const safeLog = redactSecrets(logMessage);
```

### 3. Rate Limiting
```typescript
import { createAuthRateLimiter } from "@openclaw/security";

// Always use rate limiting for sensitive endpoints
const limiter = createAuthRateLimiter();
if (!limiter.check(key).allowed) {
  throw new Error("Too many attempts");
}
```

### 4. Security Headers
```typescript
import { addSecurityHeaders } from "@openclaw/security";

// Always add security headers to HTTP responses
app.use((req, res) => {
  addSecurityHeaders(res);
  next();
});
```

### 5. Audit Logging
```typescript
import { AuditLogger } from "@openclaw/security";

// Log all security events
const logger = new AuditLogger("gateway");
logger.logAuthentication(userId, success);
```

## Testing

Run security tests:
```bash
npm test -- src/security/testing.ts
```

Or use the test suite directly:
```typescript
import { runSecurityTestSuite, printTestResults } from "@openclaw/security";

const results = runSecurityTestSuite();
printTestResults(results);
```

## Security Audit

Run the comprehensive security audit:
```bash
openclaw security audit --deep
```

## API Reference

### Input Validation

```typescript
// Command injection prevention
containsDangerousShellChars(input: string): boolean
isValidShellArgument(input: string): boolean
sanitizeShellArgument(input: string): string

// Path traversal protection
containsPathTraversal(input: string): boolean
isValidPath(input: string, allowAbsolute?: boolean): boolean

// XSS prevention
escapeHtml(input: string): string
escapeJavaScript(input: string): string
isValidUrl(input: string): boolean

// Integer validation
isValidInteger(value: unknown, min?: number, max?: number): boolean

// String length validation
isValidLength(input: string, maxLength?: number): boolean
```

### Secrets Management

```typescript
// Secrets detection
containsSecrets(input: string): boolean
findSecrets(input: string): Array<{ name, match, start, end }>

// Secrets redaction
redactSecrets(input: string, options?: RedactSecretsOptions): string

// Secret validation
validateSecret(secret: string, options?: SecretValidationOptions): boolean
generateSecureSecret(length?: number): string

// Config sanitization
sanitizeConfig(config: OpenClawConfig): OpenClawConfig
```

### Audit Logging

```typescript
class AuditLogger {
  constructor(source: string, options?: AuditLoggerOptions)
  
  log(event: AuditEvent): void
  logAuthentication(userId: string, success: boolean, options?: {...}): void
  logAuthorization(userId: string, resource: string, action: string, allowed: boolean): void
  logCommandExecution(userId: string, command: string, success: boolean): void
  
  extractRequestInfo(req: IncomingMessage): { ipAddress?, userAgent? }
}
```

### Rate Limiting

```typescript
class RateLimiter {
  check(key: string): RateLimitResult
  record(key: string): void
  getState(key: string): RateLimitState | null
  reset(key: string): void
}

function createAuthRateLimiter(options?: Partial<RateLimitOptions>): RateLimiter
function createApiRateLimiter(options?: Partial<RateLimitOptions>): RateLimiter
```

## Contributing

When contributing to OpenClaw, please follow these security guidelines:

1. Always use the input validation utilities
2. Never log secrets directly - use `sanitizeLogMessage()`
3. Use rate limiting for all public endpoints
4. Add security headers to all HTTP responses
5. Log security events using `AuditLogger`
6. Run security tests before committing

## Security Issues

For security issues, please:
1. Do not open public issues
2. Email security@openclaw.ai
3. Or submit a PR with your fix

## License

Same as OpenClaw project.
