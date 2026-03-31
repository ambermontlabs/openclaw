# OpenCLAW Security Fix Implementation Plan

**Date**: 2024  
**Version**: 1.0  
**Status**: Planning Phase

---

## Overview

This document outlines the implementation plan to address the critical and high-priority injection vulnerabilities identified in the security review.

---

## Phase 1: Critical Issues (Week 1-2)

### Task 1.1: Sandbox JavaScript Execution in canvas.eval

**Priority**: CRITICAL  
**Estimated Time**: 3-5 days

#### Current State
- Location: `cli/nodes-cli/register.canvas.ts`
- Feature allows arbitrary JavaScript execution via `canvas.eval` command
- No apparent sandboxing mechanism

#### Implementation Plan

**Step 1: Create Secure JavaScript Execution Environment**
```typescript
// New file: src/infra/sandboxed-js-executor.ts

export class SandboxedJSExecutor {
  private worker: Worker | null = null;
  private timeoutMs: number;
  
  constructor(timeoutMs: number = 5000) {
    this.timeoutMs = timeoutMs;
  }
  
  async execute(code: string, context?: Record<string, unknown>): Promise<unknown> {
    // Validate input
    if (code.length > 1000) {
      throw new Error('Code exceeds maximum length of 1000 characters');
    }
    
    // Check for dangerous patterns
    if (this.hasDangerousPatterns(code)) {
      throw new Error('Code contains dangerous patterns');
    }
    
    // Execute in Web Worker with limited privileges
    return await this.executeInWorker(code, context);
  }
  
  private hasDangerousPatterns(code: string): boolean {
    const dangerous = [
      /import\s+.*\s+from\s+/,
      /require\s*\(/,
      /fetch\s*\(/,
      /XMLHttpRequest/,
      /process\./,
      /__dirname/,
      /__filename/,
    ];
    
    return dangerous.some(pattern => pattern.test(code));
  }
  
  private async executeInWorker(
    code: string,
    context?: Record<string, unknown>
  ): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const worker = new Worker(new URL('./js-worker.js', import.meta.url));
      
      const timeout = setTimeout(() => {
        worker.terminate();
        reject(new Error('Execution timeout'));
      }, this.timeoutMs);
      
      worker.onmessage = (event) => {
        clearTimeout(timeout);
        resolve(event.data);
        worker.terminate();
      };
      
      worker.onerror = (error) => {
        clearTimeout(timeout);
        reject(error);
        worker.terminate();
      };
      
      worker.postMessage({ code, context });
    });
  }
}
```

**Step 2: Update canvas.eval Command**
```typescript
// Modified: cli/nodes-cli/register.canvas.ts

import { SandboxedJSExecutor } from '../../infra/sandboxed-js-executor.js';

const executor = new SandboxedJSExecutor(5000); // 5 second timeout

async function executeCanvasEval(code: string, opts: NodesRpcOpts) {
  try {
    const result = await executor.execute(code);
    
    // Log execution for audit
    logInfo(`Canvas eval executed (safe sandboxed)`);
    
    return {
      success: true,
      result: JSON.stringify(result, null, 2),
    };
  } catch (error) {
    logError(`Canvas eval failed: ${error.message}`);
    
    return {
      success: false,
      error: error.message,
    };
  }
}
```

**Step 3: Add Input Validation**
```typescript
// New file: src/infra/sandboxed-js-validation.ts

export function validateJSCode(code: string): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Length check
  if (code.length > 1000) {
    errors.push('Code exceeds maximum length of 1000 characters');
  }
  
  // Character whitelist
  const allowedChars = /^[a-zA-Z0-9\s\+\-\*\/\(\)\[\]\{\}\.\,\;\:\'\\"\?\!\|\&\<\>\=\_\@\#\$\%\^\&\*\(\)\~\`]+$/;
  if (!allowedChars.test(code)) {
    errors.push('Code contains disallowed characters');
  }
  
  // Dangerous patterns
  const dangerousPatterns = [
    { pattern: /import\s+.*\s+from\s+/i, message: 'Import statements not allowed' },
    { pattern: /require\s*\(/i, message: 'Require statements not allowed' },
    { pattern: /fetch\s*\(/i, message: 'Fetch calls not allowed' },
    { pattern: /XMLHttpRequest/i, message: 'XHR not allowed' },
    { pattern: /process\./i, message: 'Process access not allowed' },
    { pattern: /__dirname|__filename/i, message: 'File system access not allowed' },
    { pattern: /eval\s*\(/i, message: 'Nested eval not allowed' },
  ];
  
  for (const { pattern, message } of dangerousPatterns) {
    if (pattern.test(code)) {
      errors.push(message);
    }
  }
  
  return { valid: errors.length === 0, errors };
}
```

#### Testing
- [ ] Test with safe JavaScript code
- [ ] Test with dangerous patterns (should be blocked)
- [ ] Test with timeout scenarios
- [ ] Test memory limits

---

### Task 1.2: Validate Shell Wrapper Arguments

**Priority**: CRITICAL  
**Estimated Time**: 2-3 days

#### Current State
- Location: `infra/exec-wrapper-resolution.ts`
- Shell wrappers (bash, sh, powershell) can be used
- User input may not be properly validated

#### Implementation Plan

**Step 1: Create Shell Argument Validator**
```typescript
// New file: src/infra/shell-argument-validator.ts

export interface ShellCommand {
  command: string;
  args: string[];
}

export class ShellArgumentValidator {
  private static readonly ALLOWED_COMMANDS = new Set([
    'echo',
    'cat',
    'ls',
    'pwd',
    'date',
    'whoami',
    'uname',
    'grep',
    'sed',
    'awk',
    'cut',
    'sort',
    'uniq',
    'wc',
    'head',
    'tail',
  ]);
  
  private static readonly ALLOWED_FLAGS: Record<string, Set<string>> = {
    'echo': new Set(['-n', '-e']),
    'cat': new Set(['-n', '-T', '-s']),
    'ls': new Set(['-l', '-a', '-h', '-t', '-r']),
    'grep': new Set(['-i', '-v', '-n', '-c', '-E']),
    'sed': new Set(['-e', '-i', 's///']),
  };
  
  static validate(command: string, args: string[]): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    // Validate command name
    if (!this.ALLOWED_COMMANDS.has(command)) {
      errors.push(`Command '${command}' is not in the allowlist`);
    }
    
    // Validate arguments
    for (const arg of args) {
      if (!this.isValidArgument(arg)) {
        errors.push(`Invalid argument: ${arg}`);
      }
    }
    
    // Validate flag combinations
    if (this.ALLOWED_FLAGS[command]) {
      for (const arg of args) {
        if (arg.startsWith('-') && !this.ALLOWED_FLAGS[command].has(arg)) {
          errors.push(`Flag '${arg}' not allowed for command '${command}'`);
        }
      }
    }
    
    return { valid: errors.length === 0, errors };
  }
  
  private static isValidArgument(arg: string): boolean {
    // Only allow alphanumeric, spaces, and safe punctuation
    const safePattern = /^[a-zA-Z0-9_\-./\s\+\-=]+$/;
    
    if (!safePattern.test(arg)) {
      return false;
    }
    
    // Check for shell metacharacters
    const dangerous = [';', '|', '&', '$', '`', '>', '<', '(', ')'];
    if (dangerous.some(char => arg.includes(char))) {
      return false;
    }
    
    // Check for path traversal
    if (arg.includes('..') && !arg.startsWith('./')) {
      return false;
    }
    
    // Check for command substitution
    if (arg.includes('$(') || arg.includes('`')) {
      return false;
    }
    
    // Length limit
    if (arg.length > 256) {
      return false;
    }
    
    return true;
  }
}
```

**Step 2: Update Shell Wrapper Resolution**
```typescript
// Modified: infra/exec-wrapper-resolution.ts

import { ShellArgumentValidator } from './shell-argument-validator.js';

export function extractShellWrapperCommand(argv: string[]): { command: string; isWrapper: boolean } {
  // ... existing code ...
  
  const validator = new ShellArgumentValidator();
  const { valid, errors } = validator.validate(command, args);
  
  if (!valid) {
    throw new Error(`Invalid shell command: ${errors.join(', ')}`);
  }
  
  return { command, isWrapper };
}
```

**Step 3: Add Logging and Monitoring**
```typescript
// New file: src/infra/shell-command-audit.ts

export class ShellCommandAuditor {
  static log(command: string, args: string[], valid: boolean) {
    const auditLog = {
      timestamp: new Date().toISOString(),
      command,
      args: args.map(a => a.length > 50 ? `${a.substring(0, 50)}...` : a),
      valid,
    };
    
    logInfo(`Shell command audit: ${JSON.stringify(auditLog)}`);
  }
}
```

#### Testing
- [ ] Test with allowed commands and arguments
- [ ] Test with disallowed commands (should be blocked)
- [ ] Test with dangerous arguments (should be blocked)
- [ ] Test with path traversal attempts

---

## Phase 2: High Priority Issues (Week 3-4)

### Task 2.1: Implement Command Name Allowlist for system.run

**Priority**: HIGH  
**Estimated Time**: 2-3 days

#### Implementation Plan
```typescript
// New file: src/infra/system-run-command-allowlist.ts

export const SYSTEM_RUN_COMMAND_ALLOWLIST = new Set([
  // Basic system commands
  'ls', 'cd', 'pwd', 'echo', 'cat', 'date',
  
  // File operations
  'cp', 'mv', 'rm', 'mkdir', 'touch',
  
  // Process management
  'ps', 'kill', 'pgrep',
  
  // Network utilities (limited)
  'ping', 'curl', 'wget',
  
  // System info
  'uname', 'whoami', 'uptime', 'df', 'du',
  
  // Package managers (restricted)
  'npm', 'yarn', 'pip', 'apt-get',
]);

export interface SystemRunCommandPolicy {
  command: string;
  allowedArgs?: RegExp[];
  requireApproval?: boolean;
}

export function validateSystemRunCommand(
  command: string,
  args: string[]
): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  
  // Check if command is in allowlist
  if (!SYSTEM_RUN_COMMAND_ALLOWLIST.has(command)) {
    errors.push(`Command '${command}' is not in the allowlist`);
  }
  
  // Validate arguments
  for (const arg of args) {
    if (!isValidArgument(arg)) {
      errors.push(`Invalid argument: ${arg}`);
    }
  }
  
  return { valid: errors.length === 0, errors };
}

function isValidArgument(arg: string): boolean {
  // Only allow alphanumeric, spaces, and safe punctuation
  const safePattern = /^[a-zA-Z0-9_\-./\s\+\-=]+$/;
  
  if (!safePattern.test(arg)) {
    return false;
  }
  
  // Length limit
  if (arg.length > 256) {
    return false;
  }
  
  // No shell metacharacters
  const dangerous = [';', '|', '&', '$', '`', '>', '<', '(', ')'];
  if (dangerous.some(char => arg.includes(char))) {
    return false;
  }
  
  return true;
}
```

---

### Task 2.2: Add Path Traversal Protection

**Priority**: HIGH  
**Estimated Time**: 1-2 days

#### Implementation Plan
```typescript
// New file: src/infra/path-validation.ts

export class PathValidator {
  private static readonly MAX_PATH_DEPTH = 10;
  
  static validatePath(userPath: string, baseDir: string): { valid: boolean; resolvedPath?: string; errors: string[] } {
    const errors: string[] = [];
    
    // Normalize the path
    let resolvedPath: string;
    try {
      resolvedPath = path.resolve(baseDir, userPath);
    } catch (error) {
      errors.push('Invalid path format');
      return { valid: false, errors };
    }
    
    // Check for path traversal
    if (resolvedPath.includes('..')) {
      errors.push('Path traversal detected');
      return { valid: false, errors };
    }
    
    // Check path depth
    const depth = resolvedPath.split(path.sep).length;
    if (depth > this.MAX_PATH_DEPTH) {
      errors.push('Path depth exceeds maximum');
      return { valid: false, errors };
    }
    
    // Verify path is within base directory
    if (!resolvedPath.startsWith(baseDir + path.sep) && resolvedPath !== baseDir) {
      errors.push('Path is outside allowed directory');
      return { valid: false, errors };
    }
    
    // Check file extension (if applicable)
    const allowedExtensions = ['.txt', '.json', '.md', '.js', '.ts'];
    const ext = path.extname(resolvedPath);
    if (allowedExtensions.length > 0 && !allowedExtensions.includes(ext)) {
      errors.push(`File extension '${ext}' is not allowed`);
      return { valid: false, errors };
    }
    
    return { valid: true, resolvedPath };
  }
  
  static validateFileRead(userPath: string, baseDir: string): { valid: boolean; errors: string[] } {
    const result = this.validatePath(userPath, baseDir);
    
    if (!result.valid) {
      return result;
    }
    
    // Additional checks for file reading
    const stat = fs.statSync(result.resolvedPath!);
    
    if (stat.isDirectory()) {
      return { valid: false, errors: ['Cannot read directory'] };
    }
    
    if (stat.size > 10 * 1024 * 1024) { // 10MB limit
      return { valid: false, errors: ['File too large'] };
    }
    
    return result;
  }
}
```

---

### Task 2.3: Review Trusted Proxy Mode

**Priority**: HIGH  
**Estimated Time**: 1 day

#### Implementation Plan
```typescript
// Modified: infra/net/fetch-guard.ts

export class TrustedProxyValidator {
  private static readonly ALLOWED_PROXY_HOSTS = new Set([
    'localhost',
    '127.0.0.1',
  ]);
  
  static validateProxyUrl(url: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];
    
    try {
      const parsedUrl = new URL(url);
      
      // Only allow http/https
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        errors.push('Only http and https protocols are allowed');
      }
      
      // Check if host is in allowlist
      if (!this.ALLOWED_PROXY_HOSTS.has(parsedUrl.hostname)) {
        errors.push(`Proxy host '${parsedUrl.hostname}' is not in the allowlist`);
      }
      
      // Check port
      const port = parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80');
      if (parseInt(port) > 65535 || parseInt(port) < 1) {
        errors.push('Invalid port number');
      }
      
    } catch (error) {
      errors.push('Invalid proxy URL format');
    }
    
    return { valid: errors.length === 0, errors };
  }
}
```

---

## Phase 3: Medium Priority Issues (Week 5-6)

### Task 3.1: Audit unsafeHTML Usages

**Priority**: MEDIUM  
**Estimated Time**: 2 days

#### Implementation Plan
```typescript
// New file: src/ui/safe-html.ts

import { html, unsafeHTML } from 'lit';
import type { TemplateResult } from 'lit';

export function safeHtml(strings: TemplateStringsArray, ...values: unknown[]): TemplateResult<1> {
  // Sanitize all values before inserting
  const sanitizedValues = values.map(value => {
    if (typeof value === 'string') {
      return sanitizeHtml(value);
    }
    return value;
  });
  
  return html(strings, ...sanitizedValues);
}

export function sanitizeHtml(input: string): string {
  // Use DOMPurify for sanitization
  return DOMPurify.sanitize(input, {
    ALLOWED_TAGS: ['b', 'i', 'u', 'em', 'strong', 'a', 'span', 'div'],
    ALLOWED_ATTR: ['href', 'title', 'class', 'style'],
  });
}
```

---

### Task 3.2: Audit SQLite Queries

**Priority**: MEDIUM  
**Estimated Time**: 1-2 days

#### Implementation Plan
```typescript
// New file: src/infra/safe-sql.ts

export class SafeSQL {
  private static readonly ALLOWED_OPERATORS = new Set([
    '=', '!=', '<', '>', '<=', '>=',
    'LIKE', 'IN', 'NOT IN', 'BETWEEN',
  ]);
  
  static buildQuery(
    table: string,
    columns: string[],
    conditions: Record<string, unknown>
  ): { query: string; params: unknown[] } {
    const columnsStr = columns.join(', ');
    let query = `SELECT ${columnsStr} FROM ${table}`;
    const params: unknown[] = [];
    
    if (Object.keys(conditions).length > 0) {
      const conditionParts: string[] = [];
      
      for (const [column, value] of Object.entries(conditions)) {
        // Validate column name
        if (!this.isValidIdentifier(column)) {
          throw new Error(`Invalid column name: ${column}`);
        }
        
        if (value === undefined) {
          conditionParts.push(`${column} IS NULL`);
        } else {
          conditionParts.push(`${column} = ?`);
          params.push(value);
        }
      }
      
      query += ` WHERE ${conditionParts.join(' AND ')}`;
    }
    
    return { query, params };
  }
  
  private static isValidIdentifier(name: string): boolean {
    return /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(name);
  }
}
```

---

## Phase 4: Low Priority Issues (Week 7)

### Task 4.1: Sanitize Response Headers

**Priority**: LOW  
**Estimated Time**: 0.5 day

#### Implementation Plan
```typescript
// New file: src/infra/safe-headers.ts

export class SafeHeaders {
  private static readonly BLOCKED_HEADER_NAMES = new Set([
    'set-cookie',
    'set-cookie2',
  ]);
  
  private static readonly BLOCKED_HEADER_VALUES = [
    /\r/, // CR
    /\n/, // LF
    /\0/, // Null byte
  ];
  
  static setHeader(res: ServerResponse, name: string, value: string): void {
    // Validate header name
    if (!this.isValidHeaderName(name)) {
      throw new Error(`Invalid header name: ${name}`);
    }
    
    // Validate header value
    if (!this.isValidHeaderValue(value)) {
      throw new Error(`Invalid header value for '${name}': ${value}`);
    }
    
    res.setHeader(name, value);
  }
  
  private static isValidHeaderName(name: string): boolean {
    return /^[a-zA-Z][a-zA-Z0-9\-]*$/.test(name);
  }
  
  private static isValidHeaderValue(value: string): boolean {
    return !this.BLOCKED_HEADER_VALUES.some(pattern => pattern.test(value));
  }
}
```

---

### Task 4.2: Sanitize Logged Values

**Priority**: LOW  
**Estimated Time**: 0.5 day

#### Implementation Plan
```typescript
// New file: src/infra/safe-logging.ts

export class SafeLogger {
  private static readonly BLOCKED_LOG_PATTERNS = [
    /\r/, // CR
    /\n/, // LF
    /\0/, // Null byte
  ];
  
  static log(message: string, ...args: unknown[]): void {
    const sanitizedArgs = args.map(arg => this.sanitizeLogValue(arg));
    console.log(message, ...sanitizedArgs);
  }
  
  private static sanitizeLogValue(value: unknown): string {
    if (typeof value !== 'string') {
      return JSON.stringify(value);
    }
    
    // Remove blocked patterns
    let sanitized = value;
    for (const pattern of this.BLOCKED_LOG_PATTERNS) {
      sanitized = sanitized.replace(pattern, '');
    }
    
    // Truncate if too long
    return sanitized.substring(0, 1000);
  }
}
```

---

## Phase 5: Long-term Enhancements (Week 8+)

### Task 5.1: Implement Comprehensive Input Validation Framework

**Priority**: MEDIUM  
**Estimated Time**: 3-5 days

#### Implementation Plan
```typescript
// New file: src/infra/input-validation.ts

export class InputValidator {
  static readonly RULES = {
    // Command validation
    command: {
      pattern: /^[a-zA-Z][a-zA-Z0-9\-_]*$/,
      maxLength: 64,
    },
    
    // Argument validation
    argument: {
      pattern: /^[a-zA-Z0-9_\-./\s\+\-=]*$/,
      maxLength: 256,
    },
    
    // Path validation
    path: {
      pattern: /^[a-zA-Z0-9_\-./\s]*$/,
      maxLength: 1024,
    },
    
    // URL validation
    url: {
      pattern: /^(https?:\/\/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)$/,
      maxLength: 2048,
    },
    
    // Email validation
    email: {
      pattern: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
      maxLength: 256,
    },
    
    // Number validation
    number: {
      pattern: /^-?\d+(\.\d+)?$/,
      maxLength: 20,
    },
    
    // Boolean validation
    boolean: {
      pattern: /^(true|false|0|1|yes|no|on|off)$/i,
    },
  };
  
  static validate(value: unknown, ruleName: keyof typeof InputValidator.RULES): { valid: boolean; errors: string[] } {
    const rule = InputValidator.RULES[ruleName];
    const errors: string[] = [];
    
    if (typeof value !== 'string') {
      errors.push(`Expected string, got ${typeof value}`);
      return { valid: false, errors };
    }
    
    if (value.length > rule.maxLength) {
      errors.push(`Value exceeds maximum length of ${rule.maxLength}`);
    }
    
    if (!rule.pattern.test(value)) {
      errors.push(`Value does not match pattern for ${ruleName}`);
    }
    
    return { valid: errors.length === 0, errors };
  }
}
```

---

## Testing Strategy

### Unit Tests
- [ ] Test each validator class with valid and invalid inputs
- [ ] Test edge cases (empty strings, special characters, etc.)
- [ ] Test performance with large inputs

### Integration Tests
- [ ] Test end-to-end command execution flow
- [ ] Test file operations with malicious paths
- [ ] Test SSRF protection with various URL patterns

### Security Tests
- [ ] Run OWASP ZAP or Burp Suite on the application
- [ ] Test with injection payloads from OWASP Top 10
- [ ] Perform penetration testing

---

## Rollout Plan

### Phase 1: Internal Testing (Week 1-2)
- Deploy to staging environment
- Test with internal users
- Fix critical issues

### Phase 2: Limited Production (Week 3-4)
- Deploy to production with opt-in features
- Monitor for issues
- Collect feedback

### Phase 3: Full Rollout (Week 5+)
- Enable all features for all users
- Monitor security metrics
- Iterate based on feedback

---

## Success Metrics

### Security Metrics
- [ ] Zero critical vulnerabilities in production
- [ ] Zero high-priority vulnerabilities in production
- [ ] All injection attempts blocked and logged

### Performance Metrics
- [ ] Command execution latency < 100ms
- [ ] File operation latency < 50ms
- [ ] No performance degradation from security checks

### User Experience Metrics
- [ ] < 1% of users report issues with legitimate commands
- [ ] Clear error messages for blocked operations

---

## Rollback Plan

If issues are detected:
1. Revert to previous commit
2. Disable new security features temporarily
3. Investigate and fix issues
4. Re-deploy with fixes

---

## Maintenance

### Regular Audits
- Monthly: Review security logs
- Quarterly: Update allowlists
- Annually: Full security review

### Monitoring
- Alert on blocked injection attempts
- Monitor for false positives
- Track security metrics

---

## Conclusion

This implementation plan addresses all critical and high-priority injection vulnerabilities identified in the security review. The phased approach allows for testing and iteration while minimizing risk to production systems.

**Estimated Total Time**: 8 weeks  
**Risk Level**: LOW (phased approach with rollback plan)  
**Expected Outcome**: Significantly improved security posture against injection attacks
