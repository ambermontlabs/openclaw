/**
 * Comprehensive input validation and sanitization utilities.
 *
 * This module provides robust protection against common injection attacks
 * including command injection, path traversal, XSS, and SQL injection.
 */

import { isSafeInteger } from "../shared/number.js";

// --------------------------------------------------------------------------
// Command Injection Prevention
// --------------------------------------------------------------------------

/**
 * Check if a string contains potentially dangerous shell metacharacters.
 */
export function containsDangerousShellChars(input: string): boolean {
  const dangerousPatterns = [
    /;/,                    // Command separator
    /|/,                   // Pipe
    /&/,                    // Background/ampersand
    /`/,                    // Command substitution
    /\$\(/,                 // Command substitution $(...)
    /<[^>]/,                // Input redirection
    />[^>]/,                // Output redirection
    /\s+&&\s+/             // Command chaining
  ];

  for (const pattern of dangerousPatterns) {
    if (pattern.test(input)) {
      return true;
    }
  }

  return false;
}

/**
 * Validate that a string is safe to use in shell commands.
 * Returns true if the input contains only alphanumeric, underscore, hyphen, dot, and slash.
 */
export function isValidShellArgument(input: string): boolean {
  // Allow alphanumeric, underscore, hyphen, dot, and slash
  const safePattern = /^[a-zA-Z0-9_\-./]+$/;
  return safePattern.test(input) && input.length > 0 && input.length <= 1024;
}

/**
 * Sanitize a string for safe use in shell commands.
 * Removes all dangerous characters and returns a sanitized version.
 */
export function sanitizeShellArgument(input: string): string {
  // Remove dangerous characters but keep safe ones
  return input.replace(/[^a-zA-Z0-9_\-./]/g, "");
}

/**
 * Escape a string for safe use in shell commands.
 */
export function escapeShellArgument(input: string): string {
  // Use single quotes and escape any single quotes in the input
  return "'" + input.replace(/'/g, "'\"'\"'") + "'";
}

// --------------------------------------------------------------------------
// Path Traversal Protection
// --------------------------------------------------------------------------

/**
 * Check if a path contains directory traversal sequences.
 */
export function containsPathTraversal(input: string): boolean {
  const patterns = [
    /\.\./,           // .. traversal
    /\\/,             // Windows backslash
    /\/\.\//,         // /. directory access
    /\.\//,           // ./ current dir (can be suspicious in some contexts)
  ];

  for (const pattern of patterns) {
    if (pattern.test(input)) {
      return true;
    }
  }

  return false;
}

/**
 * Validate that a path is within allowed boundaries.
 */
export function isValidPath(input: string, allowAbsolute?: boolean): boolean {
  if (typeof input !== "string" || input.length === 0 || input.length > 4096) {
    return false;
  }

  // Check for path traversal
  if (containsPathTraversal(input)) {
    return false;
  }

  // Check for null bytes
  if (input.includes("\0")) {
    return false;
  }

  // Check for control characters
  if (/[^\x20-\x7E]/.test(input)) {
    return false;
  }

  // Check for absolute paths if not allowed
  if (!allowAbsolute && (input.startsWith("/") || input.startsWith("\\"))) {
    return false;
  }

  // Check for Windows drive letters if not allowed
  if (!allowAbsolute && /^[a-zA-Z]:/.test(input)) {
    return false;
  }

  return true;
}

/**
 * Resolve and validate a path to ensure it's within allowed boundaries.
 */
export function resolveSafePath(base: string, relative: string): string | null {
  if (!isValidPath(relative, false)) {
    return null;
  }

  // Join paths and normalize
  const path = require("path");
  const resolved = path.resolve(base, relative);

  // Ensure the resolved path is within base
  const normalizedBase = path.resolve(base);
  if (!resolved.startsWith(normalizedBase + path.sep) && resolved !== normalizedBase) {
    return null;
  }

  return resolved;
}

// --------------------------------------------------------------------------
// XSS Prevention
// --------------------------------------------------------------------------

/**
 * HTML entity mapping for escaping.
 */
const HTML_ENTITIES: Record<string, string> = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#x27;",
  "/": "&#x2F;",
};

/**
 * Escape HTML special characters to prevent XSS.
 */
export function escapeHtml(input: string): string {
  return input.replace(/[&<>"'/]/g, (char) => HTML_ENTITIES[char] || char);
}

/**
 * Escape JavaScript strings to prevent XSS.
 */
export function escapeJavaScript(input: string): string {
  return input
    .replace(/\\/g, "\\\\")
    .replace(/'/g, "\\'")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n")
    .replace(/\r/g, "\\r")
    .replace(/\u2028/g, "\\u2028") // Line separator
    .replace(/\u2029/g, "\\u2029"); // Paragraph separator
}

/**
 * Validate that a string is safe for use in HTML attributes.
 */
export function isValidHtmlAttribute(input: string): boolean {
  // Only allow alphanumeric, underscore, hyphen, dot, colon, and space
  const safePattern = /^[a-zA-Z0-9_\-.\s:]+$/;
  return safePattern.test(input) && input.length > 0 && input.length <= 1024;
}

/**
 * Validate that a string is safe for use in URLs.
 */
export function isValidUrl(input: string): boolean {
  try {
    const url = new URL(input);
    // Only allow http and https protocols
    if (!["http:", "https:"].includes(url.protocol)) {
      return false;
    }
    // Check for dangerous URL patterns
    if (url.protocol === "javascript:") {
      return false;
    }
    if (url.protocol === "data:" && !url.href.startsWith("data:image/")) {
      return false;
    }
    if (url.protocol === "file:") {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

// --------------------------------------------------------------------------
// SQL Injection Prevention (Basic)
// --------------------------------------------------------------------------

/**
 * Check if a string contains SQL injection patterns.
 */
export function containsSqlInjection(input: string): boolean {
  const sqlPatterns = [
    /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER|TRUNCATE)\b/i,
    /--/,                    // SQL comment
    /\/\*.*\*\//,           // Block comment
    /\b(OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i, // OR/AND injection
    /\b(OR|AND)\s+['"][^'"]+['"]\s*=\s*['"][^'"]+['"]/i, // String comparison
    /;\s*(SELECT|INSERT|UPDATE|DELETE|DROP)/i, // Multiple statements
    /\bEXEC\b.*\b xp_/i,     // Extended stored procedures
  ];

  for (const pattern of sqlPatterns) {
    if (pattern.test(input)) {
      return true;
    }
  }

  return false;
}

/**
 * Sanitize a string for safe use in SQL queries (basic protection).
 */
export function sanitizeSqlInput(input: string): string {
  // Remove dangerous characters
  return input.replace(/['";]/g, "");
}

// --------------------------------------------------------------------------
// Integer Validation
// --------------------------------------------------------------------------

/**
 * Validate that a value is a safe integer within bounds.
 */
export function isValidInteger(value: unknown, min?: number, max?: number): boolean {
  if (!isSafeInteger(value)) {
    return false;
  }

  const num = Number(value);
  if (min !== undefined && num < min) {
    return false;
  }
  if (max !== undefined && num > max) {
    return false;
  }

  return true;
}

// --------------------------------------------------------------------------
// String Length Validation
// --------------------------------------------------------------------------

/**
 * Validate string length to prevent DoS attacks.
 */
export function isValidLength(input: string, maxLength?: number): boolean {
  if (typeof input !== "string") {
    return false;
  }

  const length = maxLength ?? 1024 * 1024; // Default 1MB
  return input.length <= length;
}

// --------------------------------------------------------------------------
// Email Validation
// --------------------------------------------------------------------------

/**
 * Validate email address format.
 */
export function isValidEmail(input: string): boolean {
  const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailPattern.test(input) && input.length <= 320; // RFC 5321 limit
}

// --------------------------------------------------------------------------
// URL/Hostname Validation
// --------------------------------------------------------------------------

/**
 * Validate hostname format.
 */
export function isValidHostname(input: string): boolean {
  const hostnamePattern = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return hostnamePattern.test(input) && input.length <= 253;
}

// --------------------------------------------------------------------------
// JSON Validation
// --------------------------------------------------------------------------

/**
 * Validate and parse JSON with depth limit to prevent DoS.
 */
export function safeParseJson(input: string, maxDepth?: number): unknown {
  const depthLimit = maxDepth ?? 10;

  function countDepth(value: unknown, currentDepth: number): boolean {
    if (currentDepth > depthLimit) {
      return false;
    }

    if (value && typeof value === "object") {
      if (Array.isArray(value)) {
        for (const item of value) {
          if (!countDepth(item, currentDepth + 1)) {
            return false;
          }
        }
      } else {
        for (const key in value) {
          if (Object.prototype.hasOwnProperty.call(value, key)) {
            if (!countDepth((value as Record<string, unknown>)[key], currentDepth + 1)) {
              return false;
            }
          }
        }
      }
    }

    return true;
  }

  try {
    const parsed = JSON.parse(input);
    if (!countDepth(parsed, 0)) {
      throw new Error("JSON depth exceeds limit");
    }
    return parsed;
  } catch {
    return null;
  }
}

// --------------------------------------------------------------------------
// Regex Validation
// --------------------------------------------------------------------------

/**
 * Validate regex patterns to prevent ReDoS.
 */
export function isValidRegex(pattern: string, flags?: string): boolean {
  try {
    const regex = new RegExp(pattern, flags);

    // Check for potentially dangerous patterns
    const dangerousPatterns = [
      /(.+)\1{2,}/,           // Repeated capture groups
      /(\w+)+\+/,             // Nested quantifiers
      /(.+){3,}/,             // Repeated groups with quantifiers
    ];

    for (const dangerous of dangerousPatterns) {
      if (dangerous.test(pattern)) {
        return false;
      }
    }

    // Check pattern length
    if (pattern.length > 1024) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}
