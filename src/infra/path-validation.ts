/**
 * Path Validation for OpenCLAW
 * Prevents path traversal attacks in file operations
 */

import path from 'node:path';
import fs from 'node:fs';

// ============================================================================
// Path Validator Class
// ============================================================================

export class PathValidator {
  private static readonly MAX_PATH_DEPTH = 10;
  private static readonly ALLOWED_EXTENSIONS: Set<string> = new Set([
    '.txt', '.json', '.md', '.js', '.ts', '.mjs', '.cjs',
    '.jsx', '.tsx', '.html', '.css', '.csv', '.xml',
  ]);
  private static readonly MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB

  /**
   * Validate a user-provided path against a base directory
   */
  static validatePath(
    userPath: string,
    baseDir: string
  ): { valid: boolean; resolvedPath?: string; errors: string[] } {
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
    if (this.hasPathTraversal(resolvedPath)) {
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
    if (!this.isPathInside(resolvedPath, baseDir)) {
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

      if (stat.size > this.MAX_FILE_SIZE) {
        return { valid: false, errors: [`File too large (max ${this.MAX_FILE_SIZE / 1024 / 1024}MB)`] };
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

    // Check if file already exists and is a directory
    try {
      const stat = fs.statSync(result.resolvedPath!);
      if (stat.isDirectory()) {
        return { valid: false, errors: ['Cannot write to directory'] };
      }
    } catch (error) {
      // File doesn't exist, that's fine
    }

    return result;
  }

  /**
   * Check if path contains traversal attempts
   */
  private static hasPathTraversal(resolvedPath: string): boolean {
    // Check for .. in path
    if (resolvedPath.includes('..')) {
      return true;
    }

    // Check for double slashes
    if (resolvedPath.includes('//')) {
      return true;
    }

    // Check for null bytes
    if (resolvedPath.includes('\0')) {
      return true;
    }

    // Check for Windows special names
    const basename = path.basename(resolvedPath);
    const windowsSpecialNames = [
      'CON', 'PRN', 'AUX', 'NUL',
      'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
      'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
    ];

    if (windowsSpecialNames.includes(basename.toUpperCase())) {
      return true;
    }

    return false;
  }

  /**
   * Check if path is inside base directory
   */
  private static isPathInside(resolvedPath: string, baseDir: string): boolean {
    // Normalize both paths
    const normalizedResolved = path.resolve(resolvedPath);
    const normalizedBase = path.resolve(baseDir);

    // Check if resolved path starts with base directory
    return (
      normalizedResolved.startsWith(normalizedBase + path.sep) ||
      normalizedResolved === normalizedBase
    );
  }

  /**
   * Get allowed file extensions
   */
  static getAllowedExtensions(): Set<string> {
    return this.ALLOWED_EXTENSIONS;
  }

  /**
   * Check if extension is allowed
   */
  static isExtensionAllowed(ext: string): boolean {
    return this.ALLOWED_EXTENSIONS.has(ext.toLowerCase());
  }

  /**
   * Add allowed extension
   */
  static addAllowedExtension(ext: string): void {
    this.ALLOWED_EXTENSIONS.add(ext.toLowerCase());
  }

  /**
   * Remove allowed extension
   */
  static removeAllowedExtension(ext: string): void {
    this.ALLOWED_EXTENSIONS.delete(ext.toLowerCase());
  }
}

// ============================================================================
// Path Sanitizer
// ============================================================================

export class PathSanitizer {
  /**
   * Sanitize a path by removing dangerous components
   */
  static sanitizePath(userPath: string): string {
    // Remove null bytes
    let sanitized = userPath.replace(/\0/g, '');

    // Remove control characters
    sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, '');

    // Remove trailing slashes (except for root)
    if (sanitized.length > 1) {
      sanitized = sanitized.replace(/\/+$/, '');
    }

    // Remove leading ./ if present
    if (sanitized.startsWith('./')) {
      sanitized = sanitized.substring(2);
    }

    return sanitized;
  }

  /**
   * Sanitize a filename
   */
  static sanitizeFilename(filename: string): string {
    // Remove path separators
    let sanitized = filename.replace(/[\/\\]/g, '_');

    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');

    // Remove control characters
    sanitized = sanitized.replace(/[\x00-\x1F\x7F]/g, '');

    // Remove leading dots
    sanitized = sanitized.replace(/^\./, '_');

    return sanitized;
  }
}

// ============================================================================
// Path Auditor
// ============================================================================

export class PathAuditor {
  private static auditLog: Array<{
    timestamp: string;
    userPath: string;
    baseDir: string;
    resolvedPath?: string;
    valid: boolean;
    errors?: string[];
  }> = [];

  /**
   * Log a path validation
   */
  static log(
    userPath: string,
    baseDir: string,
    resolvedPath?: string,
    valid: boolean = false,
    errors?: string[]
  ): void {
    const auditEntry = {
      timestamp: new Date().toISOString(),
      userPath,
      baseDir,
      resolvedPath,
      valid,
      errors: errors?.length ? errors : undefined,
    };

    this.auditLog.push(auditEntry);

    // Keep only last 1000 entries
    if (this.auditLog.length > 1000) {
      this.auditLog.shift();
    }

    // Log to console for debugging
    if (!valid) {
      console.warn(`Path validation failed: ${JSON.stringify(auditEntry)}`);
    }
  }

  /**
   * Get audit log
   */
  static getAuditLog(): typeof this.auditLog {
    return this.auditLog;
  }

  /**
   * Clear audit log
   */
  static clearAuditLog(): void {
    this.auditLog = [];
  }
}
