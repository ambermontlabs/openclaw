# OpenClaw Security Improvements

This document describes the comprehensive security improvements made to the OpenClaw platform.

## Overview

OpenClaw has been enhanced with multiple layers of security to protect against common attack vectors including:

- Command injection
- Path traversal attacks
- Cross-site scripting (XSS)
- SQL injection
- Secrets leakage
- Rate limiting abuse
- Authentication token attacks

## New Security Modules

### 1. Input Validation (`src/security/input-validation.ts`)

Comprehensive input validation utilities to protect against injection attacks.

#### Features:
- **Command Injection Prevention**: Detect and prevent shell command injection attempts
  - `containsDangerousShellChars()`: Check for dangerous shell metacharacters
  - `isValidShellArgument()`: Validate shell arguments
  - `sanitizeShellArgument()`: Sanitize input for safe shell usage
  - `escapeShellArgument()`: Escape arguments for shell execution

- **Path Traversal Protection**: Prevent directory traversal attacks
  - `containsPathTraversal()`: Detect path traversal sequences
  - `isValidPath()`: Validate paths within allowed boundaries
  - `resolveSafePath()`: Resolve and validate paths safely

- **XSS Prevention**: Protect against cross-site scripting
  - `escapeHtml()`: Escape HTML special characters
  - `escapeJavaScript()`: Escape JavaScript strings
  - `isValidHtmlAttribute()`: Validate HTML attributes
  - `isValidUrl()`: Validate URLs safely

- **SQL Injection Prevention**: Basic SQL injection protection
  - `containsSqlInjection()`: Detect SQL injection patterns
  - `sanitizeSqlInput()`: Sanitize SQL inputs

- **Additional Validation**:
  - Integer validation with bounds checking
  - String length validation to prevent DoS
  - Email and hostname validation
  - JSON parsing with depth limits
  - Regex pattern validation to prevent ReDoS

#### Usage Example:
```typescript
import { 
  isValidShellArgument, 
  escapeHtml, 
  containsPathTraversal,
  isValidUrl
} from "@openclaw/security";

// Validate shell command
if (!isValidShellArgument(userInput)) {
  throw new Error("Invalid input");
}

// Escape HTML to prevent XSS
const safeHtml = escapeHtml(userInput);

// Check for path traversal
if (containsPathTraversal(userInput)) {
  throw new Error("Invalid path");
}

// Validate URL
if (!isValidUrl(userInput)) {
  throw new Error("Invalid URL");
}
```

### 2. Command Execution (`src/security/command-execution.ts`)

Secure command execution utilities with built-in protection.

#### Features:
- Command validation before execution
- Argument sanitization
- Command injection detection
- Whitelist-based command execution
- Safe process spawning

#### Usage Example:
```typescript
import { safeExec, validateCommand } from "@openclaw/security";

// Validate command before execution
if (!validateCommand(command)) {
  throw new Error("Invalid or dangerous command");
}

// Execute safely
const result = await safeExec(command, {
  timeout: 30000,
  maxBuffer: 1024 * 1024
});
```

### 3. Secrets Management (`src/security/secrets-management.ts`)

Comprehensive secrets detection, redaction, and validation.

#### Features:
- Secrets pattern detection
- Automatic redaction of secrets in logs
- Secret validation with security requirements
- Secure secret generation
- Config sanitization

#### Usage Example:
```typescript
import { 
  containsSecrets, 
  redactSecrets, 
  validateSecret,
  generateSecureSecret
} from "@openclaw/security";

// Check for secrets in a string
if (containsSecrets(logMessage)) {
  logMessage = redactSecrets(logMessage);
}

// Validate a secret
if (!validateSecret(password, { minLength: 16 })) {
  throw new Error("Password doesn't meet security requirements");
}

// Generate a secure secret
const token = generateSecureSecret(32);
```

### 4. HTTP Security Headers (`src/security/http-security-headers.ts`)

HTTP security headers middleware to protect against common web vulnerabilities.

#### Features:
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Strict-Transport-Security
- Referrer-Policy
- Permissions-Policy
- Cache-Control for sensitive data
- CORS security

#### Usage Example:
```typescript
import { addSecurityHeaders, createSecurityHeadersMiddleware } from "@openclaw/security";

// Add security headers to response
addSecurityHeaders(res);

// Express middleware
app.use(createSecurityHeadersMiddleware());
```

### 5. Audit Logging (`src/security/audit-logging.ts`)

Structured, secure logging for security events.

#### Features:
- Audit event categorization
- Severity levels (info, warn, error, critical)
- Automatic secrets redaction in logs
- Request information extraction
- Event tracking and correlation

#### Usage Example:
```typescript
import { AuditLogger } from "@openclaw/security";

const logger = new AuditLogger("gateway");

// Log authentication event
logger.logAuthentication(userId, success, {
  ipAddress: req.ip,
  method: "token"
});

// Log authorization event
logger.logAuthorization(userId, resource, action, allowed);

// Log command execution
logger.logCommandExecution(userId, command, success);
```

### 6. Authentication Token Security (`src/security/auth-token-security.ts`)

Enhanced authentication token security.

#### Features:
- Cryptographically secure token generation
- Token hashing and validation
- Token rotation with history
- Token binding to attributes (IP, user agent, device)
- Secure token storage
- Token expiration management

#### Usage Example:
```typescript
import { 
  generateTokenWithHash,
  TokenRotationManager,
  SecureTokenStorage
} from "@openclaw/security";

// Generate token with hash
const { token, hash } = generateTokenWithHash();

// Token rotation
const manager = new TokenRotationManager();
manager.addToken(token);

// Secure storage
const storage = new SecureTokenStorage();
storage.storeToken(userId, token);
```

### 7. Improved Rate Limiting (`src/security/improved-rate-limiting.ts`)

Comprehensive rate limiting with multiple strategies.

#### Features:
- Fixed window rate limiting
- Sliding window rate limiting
- Token bucket rate limiting
- Composite rate limiters
- Distributed rate limiting support
- Express-style middleware

#### Usage Example:
```typescript
import { createRateLimiter, createAuthRateLimiter } from "@openclaw/security";

// Create rate limiter
const limiter = createRateLimiter({
  maxRequests: 100,
  windowMs: 60 * 1000, // 1 minute
  strategy: "sliding-window"
});

// Check and record
const result = limiter.check(key);
if (result.allowed) {
  limiter.record(key);
}

// Auth rate limiter
const authLimiter = createAuthRateLimiter({
  maxRequests: 5,
  windowMs: 15 * 60 * 1000
});
```

### 8. Security Testing (`src/security/testing.ts`)

Comprehensive security testing utilities.

#### Features:
- Injection detection tests
- Input validation tests
- Secrets detection tests
- Token security tests
- Rate limiting tests

#### Usage Example:
```typescript
import { runSecurityTestSuite, printTestResults } from "@openclaw/security";

// Run complete test suite
const results = runSecurityTestSuite();

// Print results
printTestResults(results);
```

## Security Best Practices

### 1. Input Validation
Always validate and sanitize user input before processing:
```typescript
import { isValidShellArgument, escapeHtml } from "@openclaw/security";

if (!isValidShellArgument(userInput)) {
  throw new Error("Invalid input");
}

const safeHtml = escapeHtml(userInput);
```

### 2. Secrets Management
Never log secrets directly:
```typescript
import { sanitizeLogMessage } from "@openclaw/security";

const safeMessage = sanitizeLogMessage(messageWithSecrets);
console.log(safeMessage);
```

### 3. Rate Limiting
Always use rate limiting for sensitive endpoints:
```typescript
import { createAuthRateLimiter } from "@openclaw/security";

const authLimiter = createAuthRateLimiter();
app.use("/auth", createRateLimitMiddleware(authLimiter));
```

### 4. Security Headers
Always add security headers to HTTP responses:
```typescript
import { addSecurityHeaders } from "@openclaw/security";

app.use((req, res) => {
  addSecurityHeaders(res);
  next();
});
```

### 5. Audit Logging
Log all security events:
```typescript
import { AuditLogger } from "@openclaw/security";

const logger = new AuditLogger("gateway");
logger.logAuthentication(userId, success);
```

## Migration Guide

### From Old to New Security Features

1. **Replace manual validation with input-validation module**:
   ```typescript
   // Old
   if (input.includes(";") || input.includes("|")) {
     throw new Error("Invalid input");
   }
   
   // New
   import { isValidShellArgument } from "@openclaw/security";
   if (!isValidShellArgument(input)) {
     throw new Error("Invalid input");
   }
   ```

2. **Replace manual secrets redaction**:
   ```typescript
   // Old
   const safeMessage = message.replace(/password=\S+/, "password=[REDACTED]");
   
   // New
   import { redactSecrets } from "@openclaw/security";
   const safeMessage = redactSecrets(message);
   ```

3. **Replace manual rate limiting**:
   ```typescript
   // Old
   let requestCount = 0;
   if (requestCount++ > 100) {
     throw new Error("Rate limit exceeded");
   }
   
   // New
   import { createAuthRateLimiter } from "@openclaw/security";
   const limiter = createAuthRateLimiter();
   if (!limiter.check(key).allowed) {
     throw new Error("Rate limit exceeded");
   }
   limiter.record(key);
   ```

## Security Audit

Run the security audit to check for common security issues:
```bash
openclaw security audit --deep
```

## Contributing

When contributing to OpenClaw, please follow these security guidelines:

1. Always use the input validation utilities
2. Never log secrets directly
3. Use rate limiting for all public endpoints
4. Add security headers to all HTTP responses
5. Log security events using the audit logger
6. Run security tests before committing

## Support

For security issues, please contact the OpenClaw team or submit a PR with your fix.
