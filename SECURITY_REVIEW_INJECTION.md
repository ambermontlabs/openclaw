# OpenCLAW Security Review: Injection Vulnerabilities

**Date**: 2024  
**Scope**: Analysis of injection vulnerabilities similar to Burp Suite security testing  
**Repository**: OpenCLAW (https://github.com/openclaw/openclaw)

---

## Executive Summary

OpenCLAW demonstrates **generally strong security practices** for injection vulnerabilities, with multiple layers of defense in place. However, there are areas that require attention and improvement. The codebase shows awareness of common injection vectors but has some implementation gaps that could be exploited.

### Overall Security Rating: **MEDIUM-HIGH** (with improvements needed)

---

## 1. Command Injection Vulnerabilities

### ✅ Strengths
- **Safe command execution patterns**: The codebase primarily uses `spawn` with array arguments rather than shell strings
- **Windows cmd.exe protection**: Has specific validation for Windows unsafe characters (`/workspace/project/openclaw/src/process/exec.ts:14`)
- **Shell flag disabled**: Explicitly disables `shell` option to prevent injection (`exec.ts:90-97`)
- **Skill scanner detection**: Has automated scanning for dangerous exec patterns (`skill-scanner.ts:147-154`)

### ⚠️ Concerns

#### A. Shell Wrapper Command Execution
**Location**: `/workspace/project/openclaw/src/infra/exec-wrapper-resolution.ts`

```typescript
// Potential issue: Shell commands can be wrapped and executed
function extractShellWrapperCommand(argv: string[]): { command: string; isWrapper: boolean }
```

**Risk**: High  
**Severity**: CRITICAL

**Issue**: The system supports shell wrapper commands (bash, sh, powershell, etc.) which could allow command injection if user input is not properly sanitized before being passed to these wrappers.

**Recommendation**:
- Implement strict validation of shell wrapper arguments
- Use `shell: false` explicitly in all spawn calls
- Sanitize all user input before passing to shell wrappers

#### B. System Run Command Approval
**Location**: `/workspace/project/openclaw/src/node-host/invoke-system-run.ts`

```typescript
export async function resolveSystemRunCommand(params: {
  command?: unknown;
  rawCommand?: unknown;
}): ResolvedSystemRunCommand
```

**Risk**: Medium-High  
**Severity**: HIGH

**Issue**: The `rawCommand` parameter could potentially contain shell metacharacters if not properly validated.

**Recommendation**:
- Implement strict allowlist for command names
- Validate all arguments against a whitelist of safe characters
- Use `spawn` with explicit array arguments, never concatenate strings

---

## 2. Cross-Site Scripting (XSS) Vulnerabilities

### ✅ Strengths
- **DOMPurify integration**: Uses DOMPurify for HTML sanitization (`ui/src/ui/markdown.ts:1`)
- **Markdown sanitization**: Implements custom renderer that escapes HTML (`markdown.ts:176-240`)
- **URL scheme validation**: Blocks dangerous URL schemes (javascript:, data:, vbscript:) (`markdown.ts:104-114`)
- **Content Security Policy**: Uses safe tag/attribute allowlists

### ⚠️ Concerns

#### A. unsafeHTML Usage
**Location**: Multiple UI files using `unsafeHTML` directive

```typescript
// ui/src/ui/chat/grouped-render.ts:2
import { unsafeHTML } from "lit/directives/unsafe-html.js";
// ...
${unsafeHTML(toSanitizedMarkdownHtml(markdown))}
```

**Risk**: Medium  
**Severity**: MEDIUM

**Issue**: While the content is sanitized, using `unsafeHTML` implies the content might not be fully trusted. The sanitization happens, but there's a risk if DOMPurify is bypassed or misconfigured.

**Recommendation**:
- Review all `unsafeHTML` usages to ensure content is properly sanitized
- Consider using safe HTML construction with `html` template literals where possible
- Add additional CSP headers for defense in depth

#### B. Code Block Copy Functionality
**Location**: `ui/src/ui/markdown.ts:210`

```typescript
const copyBtn = `<button type="button" class="code-block-copy" data-code="${attrSafe}" ...>`;
```

**Risk**: Low-Medium  
**Severity**: LOW

**Issue**: The `attrSafe` variable uses manual escaping which could be error-prone. Should use DOMPurify's attribute sanitization.

**Recommendation**: Use `DOMPurify.sanitize()` for all attribute values, not just manual string replacement.

---

## 3. Server-Side Request Forgery (SSRF)

### ✅ Strengths
- **Guarded fetch implementation**: Has comprehensive SSRF protection (`infra/net/fetch-guard.ts`)
- **Private IP blocking**: Blocks loopback, link-local, and private IP ranges
- **DNS pinning**: Implements pinned DNS resolution to prevent DNS rebinding
- **Protocol validation**: Only allows http/https schemes

### ⚠️ Concerns

#### A. Trusted Environment Proxy Mode
**Location**: `infra/net/fetch-guard.ts:18-21`

```typescript
export const GUARDED_FETCH_MODE = {
  STRICT: "strict",
  TRUSTED_ENV_PROXY: "trusted_env_proxy",
} as const;
```

**Risk**: Medium  
**Severity**: MEDIUM

**Issue**: The `TRUSTED_ENV_PROXY` mode could bypass SSRF protections if environment variables are controlled by an attacker.

**Recommendation**:
- Ensure `TRUSTED_ENV_PROXY` mode is only enabled in trusted environments
- Validate proxy URLs against allowlist
- Add additional logging for proxy usage

#### B. URL Validation in Web Fetch Tool
**Location**: `agents/tools/web-fetch.ts`

```typescript
const response = await fetch(url, { ... });
```

**Risk**: Medium  
**Severity**: MEDIUM

**Issue**: Need to verify all URLs passed to `web-fetch` are validated through SSRF protection.

**Recommendation**: Ensure all external URLs go through `fetchWithSsrFGuard` and never use native fetch directly with user-controlled URLs.

---

## 4. Path Traversal Vulnerabilities

### ⚠️ Concerns

#### A. File System Operations
**Location**: Multiple files using `path.join` and file operations

```typescript
// cli/config-set-input.ts:1
const raw = fs.readFileSync(pathname, "utf8");
```

**Risk**: Medium  
**Severity**: MEDIUM

**Issue**: While the codebase uses `path.join`, there's no clear evidence of path validation to prevent directory traversal attacks (e.g., `../../../etc/passwd`).

**Recommendation**:
- Implement path validation using `path.resolve()` and verify the result is within expected directories
- Use `isPathInside` utility where available (already exists in security module)
- Add explicit validation for all user-controlled file paths

#### B. Template File Loading
**Location**: `cli/gateway-cli/dev.ts`

```typescript
const raw = await fs.promises.readFile(path.join(templateDir, name), "utf-8");
```

**Risk**: Medium  
**Severity**: MEDIUM

**Issue**: User-controlled `name` parameter could enable path traversal.

**Recommendation**:
- Validate `name` against allowlist of template names
- Use `path.resolve()` and verify the path is within `templateDir`

---

## 5. SQL Injection Vulnerabilities

### ✅ Strengths
- **SQLite usage**: Uses SQLite for memory storage with parameterized queries (implied by modern ORMs)

### ⚠️ Concerns

#### A. Query Construction
**Location**: `agents/memory-search.ts`

```typescript
driver: "sqlite"
```

**Risk**: Low-Medium  
**Severity**: LOW

**Issue**: Need to verify all database queries use parameterized statements and never concatenate user input into SQL strings.

**Recommendation**:
- Audit all SQLite queries to ensure parameterization
- Use prepared statements with bound parameters
- Consider using an ORM with built-in protection

---

## 6. Template Injection Vulnerabilities

### ✅ Strengths
- **No eval() usage**: No evidence of dynamic code execution with `eval()`
- **Safe template rendering**: Uses Lit HTML with proper escaping

### ⚠️ Concerns

#### A. Code Evaluation in Canvas
**Location**: `cli/nodes-cli/register.canvas.ts`

```typescript
.argument("[js]", "JavaScript to evaluate")
.option("--js <code>", "JavaScript to evaluate")
```

**Risk**: High  
**Severity**: CRITICAL

**Issue**: The canvas.eval command allows execution of arbitrary JavaScript code. If user input is not properly sanitized, this could lead to remote code execution.

**Recommendation**:
- Implement strict sandboxing for JavaScript execution
- Use a secure VM or Web Worker with limited privileges
- Add input validation and size limits
- Consider using a safe expression evaluator instead of full JS execution

---

## 7. Header Injection Vulnerabilities

### ⚠️ Concerns

#### A. HTTP Response Headers
**Location**: `gateway/server/plugins-http.ts`

```typescript
if (!res.headersSent) {
  // Set headers
}
```

**Risk**: Low-Medium  
**Severity**: LOW

**Issue**: Need to ensure response headers are properly sanitized and don't contain user-controlled input.

**Recommendation**:
- Validate all header names and values
- Block newline characters in headers (prevents header injection)
- Use allowlist for header names

---

## 8. Log Injection (CRLF)

### ⚠️ Concerns

#### A. Logging User Input
**Location**: Multiple files with logging

```typescript
logWarn(`security: system.run approval cwd drift blocked (runId=${phase.runId})`);
```

**Risk**: Low  
**Severity**: LOW

**Issue**: If user-controlled input is logged without sanitization, it could enable log injection attacks.

**Recommendation**:
- Sanitize user input before logging
- Block newline characters in logged values
- Use structured logging with proper escaping

---

## 9. Dependency Injection & Supply Chain

### ✅ Strengths
- **Skill scanner**: Automated scanning for malicious patterns in skills
- **Audit system**: Has security audit functionality (`security/audit.ts`)

### ⚠️ Concerns

#### A. Skill Execution
**Location**: `security/skill-scanner.ts`

```typescript
const LINE_RULES: LineRule[] = [
  {
    ruleId: "dangerous-exec",
    severity: "critical",
    message: "Shell command execution detected (child_process)",
    pattern: /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/,
  },
  // ...
];
```

**Risk**: Medium  
**Severity**: MEDIUM

**Issue**: The skill scanner can detect dangerous patterns but may have false positives/negatives. Need to ensure all skills are scanned before execution.

**Recommendation**:
- Implement mandatory skill scanning before installation
- Add signature verification for official skills
- Create a trusted skill allowlist

---

## 10. Configuration Injection

### ⚠️ Concerns

#### A. Environment Variable Handling
**Location**: Multiple files accessing `process.env`

```typescript
const raw = process.env.OPENCLAW_CONFIG_PATH;
```

**Risk**: Medium  
**Severity**: MEDIUM

**Issue**: Environment variables could be manipulated to inject malicious configuration.

**Recommendation**:
- Validate all environment variable values
- Use type-safe configuration loading
- Implement configuration signing/verification

---

## Critical Findings Summary

### 🔴 CRITICAL Issues (Immediate Action Required)

1. **Canvas JavaScript Execution**: The `canvas.eval` command allows arbitrary JS execution without apparent sandboxing
   - **Recommendation**: Implement strict sandboxing or disable this feature

2. **Shell Wrapper Command Injection**: Shell wrappers could allow command injection if user input is not properly sanitized
   - **Recommendation**: Implement strict validation of all shell wrapper arguments

### 🟠 HIGH Priority Issues

3. **System Run Command Validation**: The `rawCommand` parameter needs stricter validation
   - **Recommendation**: Implement allowlist for command names and validate all arguments

4. **Path Traversal in File Operations**: User-controlled file paths need validation
   - **Recommendation**: Implement path validation using `path.resolve()` and allowlist

5. **Trusted Environment Proxy Bypass**: The trusted proxy mode could bypass SSRF protections
   - **Recommendation**: Restrict to trusted environments only with additional validation

### 🟡 MEDIUM Priority Issues

6. **unsafeHTML Usage**: Multiple UI components use unsafeHTML which could be risky
   - **Recommendation**: Review all usages and ensure proper sanitization

7. **SQL Injection Risk**: Need to verify all database queries use parameterization
   - **Recommendation**: Audit SQLite queries for proper parameterization

8. **Header Injection**: Response headers need validation
   - **Recommendation**: Sanitize all header values and block newlines

### 🟢 LOW Priority Issues

9. **Log Injection**: User input in logs needs sanitization
   - **Recommendation**: Sanitize logged values

10. **Code Block Attribute Escaping**: Manual escaping in code blocks could be error-prone
    - **Recommendation**: Use DOMPurify for attribute sanitization

---

## Recommendations Summary

### Immediate Actions
1. **Sandbox JavaScript execution** in canvas.eval feature
2. **Validate all shell wrapper arguments** with strict allowlists
3. **Implement command name allowlist** for system.run

### Short-term Improvements
1. Add path traversal protection to all file operations
2. Review and restrict trusted proxy mode usage
3. Audit unsafeHTML usages in UI components

### Long-term Enhancements
1. Implement comprehensive input validation framework
2. Add automated security scanning to CI/CD pipeline
3. Create security testing documentation and guidelines

---

## Testing Recommendations (Burp Suite Style)

### Automated Scanning
1. **Static Analysis**: Run automated scanners on all code changes
2. **Dynamic Analysis**: Test running instances with Burp Suite Pro
3. **API Testing**: Scan all HTTP endpoints for injection vulnerabilities

### Manual Testing Checklist
- [ ] Test command injection with shell metacharacters (`;`, `|`, `&`, `$()`)
- [ ] Test XSS with payload encoding (URL, HTML, JavaScript)
- [ ] Test SSRF with private IP ranges and metadata endpoints
- [ ] Test path traversal with `../` sequences
- [ ] Test SQL injection with UNION attacks and boolean-based payloads
- [ ] Test header injection with CRLF sequences
- [ ] Test template injection with expression language payloads

### Burp Suite Configuration
```
Target Scope:
- Allow: All application endpoints
- Exclude: Static assets, third-party CDNs

Scanner Settings:
- Enable all injection tests
- Increase test intensity for critical endpoints
- Configure custom payloads for OpenCLAW-specific features

Proxy Settings:
- Intercept all requests to test input validation
- Modify requests to test edge cases
```

---

## Compliance & Standards

This review aligns with:
- **OWASP Top 10 2021**: Injection Flaws (A3)
- **CWE/SANS Top 25**: SQL Injection, OS Command Injection, XSS
- **PCI DSS**: Requirement 6.5 for injection prevention

---

## Conclusion

OpenCLAW has implemented several security controls that demonstrate awareness of common injection vulnerabilities. However, the complexity of the system (AI agent platform with command execution capabilities) creates unique attack surfaces that require ongoing attention.

**Key Strengths**:
- Good use of sanitization libraries (DOMPurify)
- SSRF protection infrastructure
- Automated skill scanning

**Key Weaknesses**:
- Canvas JavaScript execution without apparent sandboxing
- Potential path traversal in file operations
- Shell wrapper command injection risks

**Overall Assessment**: The platform is **reasonably secure** but requires immediate attention to the critical issues identified above before handling untrusted user input or deploying in production environments with external users.

---

*This security review was conducted on the OpenCLAW codebase as of 2024. Regular security audits and penetration testing are recommended.*
