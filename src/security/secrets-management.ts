/**
 * Enhanced secrets management utilities.
 *
 * This module provides comprehensive protection against secrets leakage
 * in logs, error messages, and other outputs.
 */

import type { OpenClawConfig } from "../config/config.js";

// --------------------------------------------------------------------------
// Secrets Detection
// --------------------------------------------------------------------------

/**
 * Patterns that may indicate secrets in strings.
 */
const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp }> = [
  { name: "API Key (generic)", pattern: /(?:api[_-]?key|apikey)[=:\s]+[a-zA-Z0-9_-]{16,}/gi },
  { name: "AWS Access Key", pattern: /AKIA[0-9A-Z]{16}/gi },
  { name: "AWS Secret Key", pattern: /(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret)[=:\s]+[a-zA-Z0-9\/+=]{40}/gi },
  { name: "GitHub Token", pattern: /ghp_[a-zA-Z0-9]{36}/gi },
  { name: "GitHub PAT", pattern: /gho_[a-zA-Z0-9]{36}/gi },
  { name: "GitHub App Token", pattern: /ghs_[a-zA-Z0-9]{36}/gi },
  { name: "GitHub Refresh Token", pattern: /ghr_[a-zA-Z0-9]{36}/gi },
  { name: "Slack Token", pattern: /xox[baprs]-[0-9]{10,}-[0-9]{10,}[a-zA-Z0-9]*/gi },
  { name: "Generic Secret", pattern: /(?:secret|password|passwd|pwd)[=:\s]+[^\s]{8,}/gi },
  { name: "Private Key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/gi },
  { name: "JWT Token", pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*/gi },
  { name: "Database Connection String", pattern: /(?:mongodb|mysql|postgres|redis):\/\/[^\s]+:[^\s]+@[^\s]+/gi },
  { name: "Bearer Token", pattern: /(?:Authorization|Bearer)[=:\s]+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/gi },
  { name: "Email in Secret Context", pattern: /(?:password|secret)[=:\s]*[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi },
];

/**
 * Check if a string contains potential secrets.
 */
export function containsSecrets(input: string): boolean {
  for (const { pattern } of SECRET_PATTERNS) {
    if (pattern.test(input)) {
      return true;
    }
  }
  return false;
}

/**
 * Find all secrets in a string.
 */
export function findSecrets(input: string): Array<{ name: string; match: string; start: number; end: number }> {
  const found: Array<{ name: string; match: string; start: number; end: number }> = [];

  for (const { name, pattern } of SECRET_PATTERNS) {
    const matches = input.matchAll(pattern);
    for (const match of matches) {
      if (match.index !== undefined && match[0]) {
        found.push({
          name,
          match: match[0],
          start: match.index,
          end: match.index + match[0].length,
        });
      }
    }
  }

  // Sort by position
  found.sort((a, b) => a.start - b.start);

  return found;
}

// --------------------------------------------------------------------------
// Secrets Redaction
// --------------------------------------------------------------------------

/**
 * Options for redacting secrets.
 */
export interface RedactSecretsOptions {
  /** Character to use for redaction (default: *) */
  redactChar?: string;
  /** Length of secrets to preserve at start/end (default: 4) */
  preserveLength?: number;
  /** Redact all matches or just the first one (default: true) */
  redactAll?: boolean;
}

/**
 * Default options for redacting secrets.
 */
const DEFAULT_REDACT_OPTIONS: Required<RedactSecretsOptions> = {
  redactChar: "*",
  preserveLength: 4,
  redactAll: true,
};

/**
 * Redact secrets from a string.
 */
export function redactSecrets(
  input: string,
  options?: RedactSecretsOptions
): string {
  const config = { ...DEFAULT_REDACT_OPTIONS, ...options };
  let result = input;

  const foundSecrets = findSecrets(input);

  if (foundSecrets.length === 0) {
    return input;
  }

  // Process in reverse order to maintain correct indices
  for (let i = foundSecrets.length - 1; i >= 0; i--) {
    const secret = foundSecrets[i];
    result = redactString(result, secret.start, secret.end, config);
  }

  return result;
}

/**
 * Redact a specific range in a string.
 */
function redactString(
  input: string,
  start: number,
  end: number,
  options: Required<RedactSecretsOptions>
): string {
  const { redactChar, preserveLength } = options;

  // Don't redact if the secret is too short
  if (end - start <= preserveLength * 2) {
    return input;
  }

  const before = input.slice(0, start + preserveLength);
  const after = input.slice(end - preserveLength);
  const redactedLength = end - start - preserveLength * 2;
  const redacted = redactChar.repeat(redactedLength);

  return input.slice(0, start + preserveLength) + redacted + after;
}

/**
 * Redact secrets from an object (recursively).
 */
export function redactSecretsFromObject(
  input: unknown,
  options?: RedactSecretsOptions
): unknown {
  const config = { ...DEFAULT_REDACT_OPTIONS, ...options };

  if (typeof input === "string") {
    return redactSecrets(input, config);
  }

  if (Array.isArray(input)) {
    return input.map((item) => redactSecretsFromObject(item, config));
  }

  if (input && typeof input === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input)) {
      // Don't redact certain keys
      if (key.toLowerCase().includes("id") || key.toLowerCase().includes("name")) {
        result[key] = value;
      } else {
        result[key] = redactSecretsFromObject(value, config);
      }
    }
    return result;
  }

  return input;
}

// --------------------------------------------------------------------------
// Secrets in Logs
// --------------------------------------------------------------------------

/**
 * Check if a log message contains secrets.
 */
export function logContainsSecrets(message: string): boolean {
  return containsSecrets(message);
}

/**
 * Sanitize a log message by redacting secrets.
 */
export function sanitizeLogMessage(message: string): string {
  return redactSecrets(message);
}

/**
 * Log a message with secrets redacted.
 */
export function safeLog(message: string, level: "info" | "warn" | "error" = "info"): void {
  const sanitized = sanitizeLogMessage(message);
  
  // Use console methods directly to avoid circular dependencies
  switch (level) {
    case "info":
      console.log(sanitized);
      break;
    case "warn":
      console.warn(sanitized);
      break;
    case "error":
      console.error(sanitized);
      break;
  }
}

// --------------------------------------------------------------------------
// Secrets in Error Messages
// --------------------------------------------------------------------------

/**
 * Sanitize an error message by redacting secrets.
 */
export function sanitizeErrorMessage(error: Error | string): string {
  const message = typeof error === "string" ? error : error.message;
  return redactSecrets(message);
}

/**
 * Create a safe error that doesn't leak secrets.
 */
export function createSafeError(message: string, options?: { cause?: Error }): Error {
  const safeMessage = sanitizeErrorMessage(message);
  return new Error(safeMessage, options?.cause ? { cause: options.cause } : undefined);
}

// --------------------------------------------------------------------------
// Secrets in Config
// --------------------------------------------------------------------------

/**
 * Check if a config object contains secrets.
 */
export function configContainsSecrets(config: OpenClawConfig): boolean {
  const configString = JSON.stringify(config);
  return containsSecrets(configString);
}

/**
 * Sanitize a config object by redacting secrets.
 */
export function sanitizeConfig(config: OpenClawConfig): OpenClawConfig {
  return redactSecretsFromObject(config) as OpenClawConfig;
}

/**
 * Get a safe representation of config for logging.
 */
export function getSafeConfigSnapshot(config: OpenClawConfig): Record<string, unknown> {
  const sanitized = sanitizeConfig(config);
  
  // Remove sensitive fields entirely
  const safe: Record<string, unknown> = { ...sanitized };
  
  // Remove common secret fields
  const sensitiveKeys = [
    "token",
    "password",
    "secret",
    "apiKey",
    "api_key",
    "auth",
    "credentials",
  ];
  
  for (const key of sensitiveKeys) {
    delete safe[key];
  }
  
  return safe;
}

// --------------------------------------------------------------------------
// Secrets Validation
// --------------------------------------------------------------------------

/**
 * Validate that a secret meets security requirements.
 */
export interface SecretValidationOptions {
  /** Minimum length (default: 16) */
  minLength?: number;
  /** Maximum length (default: 1024) */
  maxLength?: number;
  /** Require uppercase letters (default: true) */
  requireUppercase?: boolean;
  /** Require lowercase letters (default: true) */
  requireLowercase?: boolean;
  /** Require numbers (default: true) */
  requireNumbers?: boolean;
  /** Require special characters (default: true) */
  requireSpecialChars?: boolean;
}

/**
 * Default validation options.
 */
const DEFAULT_SECRET_OPTIONS: Required<SecretValidationOptions> = {
  minLength: 16,
  maxLength: 1024,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
};

/**
 * Validate a secret against security requirements.
 */
export function validateSecret(secret: string, options?: SecretValidationOptions): boolean {
  const config = { ...DEFAULT_SECRET_OPTIONS, ...options };

  // Check length
  if (secret.length < config.minLength || secret.length > config.maxLength) {
    return false;
  }

  // Check character requirements
  if (config.requireUppercase && !/[A-Z]/.test(secret)) {
    return false;
  }

  if (config.requireLowercase && !/[a-z]/.test(secret)) {
    return false;
  }

  if (config.requireNumbers && !/[0-9]/.test(secret)) {
    return false;
  }

  if (config.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(secret)) {
    return false;
  }

  // Check for common weak patterns
  const weakPatterns = [
    /(?:password|secret)[0-9]+$/i,
    /^[a-z]+$/, // Only lowercase
    /^[A-Z]+$/, // Only uppercase
    /^[0-9]+$/, // Only numbers
  ];

  for (const pattern of weakPatterns) {
    if (pattern.test(secret)) {
      return false;
    }
  }

  return true;
}

/**
 * Generate a secure random secret.
 */
export function generateSecureSecret(length: number = 32): string {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:',.<>?";
  let secret = "";
  
  // Use crypto.randomInt if available
  try {
    const { randomInt } = require("crypto");
    
    for (let i = 0; i < length; i++) {
      const randomIndex = randomInt(0, chars.length);
      secret += chars[randomIndex];
    }
  } catch {
    // Fallback to Math.random if crypto is not available
    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * chars.length);
      secret += chars[randomIndex];
    }
  }

  return secret;
}
