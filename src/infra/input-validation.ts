/**
 * Input Validation Framework for OpenCLAW
 * Provides comprehensive input validation utilities to prevent injection attacks
 */

// ============================================================================
// Input Validation Rules
// ============================================================================

export const InputValidationRules = {
  // Command validation - only alphanumeric, hyphens, underscores
  command: {
    pattern: /^[a-zA-Z][a-zA-Z0-9\-_]*$/,
    maxLength: 64,
    description: 'Command names must start with a letter and contain only alphanumeric characters, hyphens, and underscores',
  },

  // Argument validation - safe character set
  argument: {
    pattern: /^[a-zA-Z0-9_\-./\s\+\-=]*$/,
    maxLength: 256,
    description: 'Arguments must contain only safe characters (alphanumeric, underscore, hyphen, dot, slash, space, plus, minus, equals)',
  },

  // Path validation
  path: {
    pattern: /^[a-zA-Z0-9_\-./\s]*$/,
    maxLength: 1024,
    description: 'Paths must contain only safe characters',
  },

  // URL validation - http/https only
  url: {
    pattern: /^https?:\/\/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$/i,
    maxLength: 2048,
    description: 'URLs must use http or https protocol',
  },

  // Email validation
  email: {
    pattern: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
    maxLength: 256,
    description: 'Valid email address format',
  },

  // Number validation
  number: {
    pattern: /^-?\d+(\.\d+)?$/,
    maxLength: 20,
    description: 'Valid number format',
  },

  // Boolean validation
  boolean: {
    pattern: /^(true|false|0|1|yes|no|on|off)$/i,
    description: 'Valid boolean value',
  },

  // Filename validation
  filename: {
    pattern: /^[a-zA-Z0-9_\-\.]+$/,
    maxLength: 255,
    description: 'Valid filename format',
  },

  // Alphanumeric validation
  alphanumeric: {
    pattern: /^[a-zA-Z0-9]+$/,
    maxLength: 128,
    description: 'Alphanumeric characters only',
  },

  // Safe text validation (no control characters)
  safeText: {
    pattern: /^[^\x00-\x1F\x7F]+$/,
    maxLength: 10000,
    description: 'Text without control characters',
  },
} as const;

// ============================================================================
// Input Validator Class
// ============================================================================

export class InputValidator {
  private static readonly BLOCKED_PATTERNS = [
    // Shell metacharacters
    /;/,           // Semicolon
    /\|/,          // Pipe
    /&/,           // Ampersand
    /\$\(/,        // Command substitution $
    /`/,           // Backtick
    /\$[a-zA-Z_]/, // Variable expansion

    // Path traversal
    /\.\./,        // Double dot
    /\/\//,        // Double slash

    // URL schemes (except http/https)
    /javascript:/i,
    /data:/i,
    /vbscript:/i,
    /file:/i,

    // SQL injection patterns
    /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER|TRUNCATE)\b/i,
    /--/,          // SQL comment
    /\/\*/,        // Block comment start

    // XSS patterns
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,  // Event handlers

    // Command injection patterns
    /\b(exec|system|shell_exec|passthru|eval)\s*\(/i,
    /\b(cat|ls|cd|rm|mv|cp)\s+/, // Basic commands with arguments
  ];

  /**
   * Validate a value against a rule
   */
  static validate(value: unknown, ruleName: keyof typeof InputValidationRules): { valid: boolean; errors: string[] } {
    const rule = InputValidationRules[ruleName];
    const errors: string[] = [];

    // Check if value is a string
    if (typeof value !== 'string') {
      errors.push(`Expected string, got ${typeof value}`);
      return { valid: false, errors };
    }

    // Check length
    if (value.length > rule.maxLength) {
      errors.push(`Value exceeds maximum length of ${rule.maxLength} characters`);
    }

    // Check pattern
    if (!rule.pattern.test(value)) {
      errors.push(`Value does not match pattern for ${ruleName}`);
    }

    // Check for blocked patterns
    for (const pattern of this.BLOCKED_PATTERNS) {
      if (pattern.test(value)) {
        errors.push('Value contains blocked patterns');
        break;
      }
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Validate a command name
   */
  static validateCommand(command: string): { valid: boolean; errors: string[] } {
    return this.validate(command, 'command');
  }

  /**
   * Validate an argument
   */
  static validateArgument(arg: string): { valid: boolean; errors: string[] } {
    return this.validate(arg, 'argument');
  }

  /**
   * Validate a path
   */
  static validatePath(path: string): { valid: boolean; errors: string[] } {
    return this.validate(path, 'path');
  }

  /**
   * Validate a URL
   */
  static validateUrl(url: string): { valid: boolean; errors: string[] } {
    return this.validate(url, 'url');
  }

  /**
   * Validate an email
   */
  static validateEmail(email: string): { valid: boolean; errors: string[] } {
    return this.validate(email, 'email');
  }

  /**
   * Validate a number
   */
  static validateNumber(value: string): { valid: boolean; errors: string[] } {
    return this.validate(value, 'number');
  }

  /**
   * Validate a boolean
   */
  static validateBoolean(value: string): { valid: boolean; errors: string[] } {
    return this.validate(value, 'boolean');
  }

  /**
   * Validate a filename
   */
  static validateFilename(filename: string): { valid: boolean; errors: string[] } {
    return this.validate(filename, 'filename');
  }

  /**
   * Validate safe text
   */
  static validateSafeText(text: string): { valid: boolean; errors: string[] } {
    return this.validate(text, 'safeText');
  }

  /**
   * Validate multiple values at once
   */
  static validateMultiple(
    entries: Array<{ value: unknown; ruleName: keyof typeof InputValidationRules }>
  ): { [key: string]: { valid: boolean; errors: string[] } } {
    const results: { [key: string]: { valid: boolean; errors: string[] } } = {};

    for (const entry of entries) {
      results[entry.ruleName] = this.validate(entry.value, entry.ruleName);
    }

    return results;
  }
}

// ============================================================================
// Path Validator (Specialized)
// ============================================================================

import path from 'node:path';
import fs from 'node:fs';

export class PathValidator {
  private static readonly MAX_PATH_DEPTH = 10;
  private static readonly ALLOWED_EXTENSIONS: Set<string> = new Set([
    '.txt', '.json', '.md', '.js', '.ts', '.mjs', '.cjs',
    '.jsx', '.tsx', '.html', '.css', '.csv', '.xml',
  ]);

  /**
   * Validate a user-provided path against a base directory
   */
  static validatePath(
    userPath: string,
    baseDir: string
  ): { valid: boolean; resolvedPath?: string; errors: string[] } {
    const errors: string[] = [];

    // First validate the path format
    const validation = InputValidator.validatePath(userPath);
    if (!validation.valid) {
      errors.push(...validation.errors);
      return { valid: false, errors };
    }

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
      errors.push(`Path depth exceeds maximum of ${this.MAX_PATH_DEPTH}`);
      return { valid: false, errors };
    }

    // Verify path is within base directory
    if (!resolvedPath.startsWith(baseDir + path.sep) && resolvedPath !== baseDir) {
      errors.push('Path is outside allowed directory');
      return { valid: false, errors };
    }

    // Check file extension (if applicable)
    const ext = path.extname(resolvedPath).toLowerCase();
    if (this.ALLOWED_EXTENSIONS.size > 0 && !this.ALLOWED_EXTENSIONS.has(ext)) {
      errors.push(`File extension '${ext}' is not allowed`);
      return { valid: false, errors };
    }

    return { valid: true, resolvedPath };
  }

  /**
   * Validate a file read operation
   */
  static validateFileRead(
    userPath: string,
    baseDir: string
  ): { valid: boolean; resolvedPath?: string; errors: string[] } {
    const result = this.validatePath(userPath, baseDir);

    if (!result.valid) {
      return result;
    }

    // Additional checks for file reading
    try {
      const stat = fs.statSync(result.resolvedPath!);

      if (stat.isDirectory()) {
        return { valid: false, errors: ['Cannot read directory'] };
      }

      if (stat.size > 10 * 1024 * 1024) { // 10MB limit
        return { valid: false, errors: ['File too large (max 10MB)'] };
      }
    } catch (error) {
      return { valid: false, errors: ['File does not exist or cannot be accessed'] };
    }

    return result;
  }

  /**
   * Validate a file write operation
   */
  static validateFileWrite(
    userPath: string,
    baseDir: string
  ): { valid: boolean; resolvedPath?: string; errors: string[] } {
    const result = this.validatePath(userPath, baseDir);

    if (!result.valid) {
      return result;
    }

    // Check if parent directory exists
    const parentDir = path.dirname(result.resolvedPath!);
    try {
      if (!fs.existsSync(parentDir)) {
        return { valid: false, errors: ['Parent directory does not exist'] };
      }
    } catch (error) {
      return { valid: false, errors: ['Cannot access parent directory'] };
    }

    return result;
  }
}

// ============================================================================
// Command Validator
// ============================================================================

export class CommandValidator {
  private static readonly ALLOWED_COMMANDS = new Set([
    // Basic system commands
    'echo', 'cat', 'ls', 'pwd', 'date', 'whoami', 'uname',
    'hostname', 'uptime', 'df', 'du', 'top', 'ps',

    // File operations
    'cp', 'mv', 'rm', 'mkdir', 'touch', 'chmod', 'chown',

    // Text processing
    'grep', 'sed', 'awk', 'cut', 'sort', 'uniq', 'wc',
    'head', 'tail', 'tr', 'fold', 'paste',

    // Network utilities (limited)
    'ping', 'curl', 'wget', 'nc', 'netstat',

    // Package managers (restricted)
    'npm', 'yarn', 'pip', 'apt-get', 'yum',

    // Compression
    'tar', 'gzip', 'gunzip', 'unzip', 'zip',

    // System info
    'env', 'export', 'printenv',
  ]);

  /**
   * Validate a command name
   */
  static validateCommand(command: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check if command is in allowlist
    if (!this.ALLOWED_COMMANDS.has(command)) {
      errors.push(`Command '${command}' is not in the allowlist`);
    }

    // Validate command format
    const validation = InputValidator.validateCommand(command);
    if (!validation.valid) {
      errors.push(...validation.errors);
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Validate command arguments
   */
  static validateArguments(args: string[]): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    for (const arg of args) {
      const validation = InputValidator.validateArgument(arg);
      if (!validation.valid) {
        errors.push(...validation.errors);
      }
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Validate a complete command
   */
  static validate(
    command: string,
    args: string[]
  ): { valid: boolean; errors: string[] } {
    const commandErrors = this.validateCommand(command);
    const argsErrors = this.validateArguments(args);

    return {
      valid: commandErrors.valid && argsErrors.valid,
      errors: [...commandErrors.errors, ...argsErrors.errors],
    };
  }
}

// ============================================================================
// URL Validator
// ============================================================================

export class UrlValidator {
  private static readonly ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);
  private static readonly BLOCKED_HOSTS = new Set([
    'localhost',
    '127.0.0.1',
    '::1',
    '0.0.0.0',
    '255.255.255.255',
  ]);

  /**
   * Validate a URL
   */
  static validateUrl(url: string): { valid: boolean; parsed?: URL; errors: string[] } {
    const errors: string[] = [];

    // First validate format
    const validation = InputValidator.validateUrl(url);
    if (!validation.valid) {
      errors.push(...validation.errors);
      return { valid: false, errors };
    }

    // Parse the URL
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch (error) {
      errors.push('Invalid URL format');
      return { valid: false, errors };
    }

    // Check protocol
    if (!this.ALLOWED_PROTOCOLS.has(parsedUrl.protocol)) {
      errors.push(`Protocol '${parsedUrl.protocol}' is not allowed`);
    }

    // Check for private IP addresses
    const hostname = parsedUrl.hostname;
    if (this.BLOCKED_HOSTS.has(hostname)) {
      errors.push('Private IP addresses are not allowed');
    }

    // Check port
    const port = parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80');
    const portNum = parseInt(port, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      errors.push('Invalid port number');
    }

    return { valid: errors.length === 0, parsed: parsedUrl, errors };
  }
}

// ============================================================================
// Export utilities
// ============================================================================

export function sanitizeHtml(input: string): string {
  // Basic HTML sanitization
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function sanitizeLogValue(value: string): string {
  // Remove control characters and newlines
  return value.replace(/[\r\n\t\x00-\x1F\x7F]/g, '');
}

export function sanitizeHeaderValue(value: string): string {
  // Remove newlines and control characters
  return value.replace(/[\r\n]/g, '');
}

export function isValidHeaderName(name: string): boolean {
  return /^[a-zA-Z][a-zA-Z0-9\-]*$/.test(name);
}
