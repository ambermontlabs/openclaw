/**
 * Safe Headers for OpenCLAW
 * Prevents header injection attacks
 */

import type { ServerResponse } from 'node:http';

// ============================================================================
// Safe Headers Validator
// ============================================================================

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

  /**
   * Set a header safely
   */
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

  /**
   * Set a header if not already sent
   */
  static setHeaderIfNotSent(
    res: ServerResponse,
    name: string,
    value: string
  ): boolean {
    if (res.headersSent) {
      return false;
    }

    this.setHeader(res, name, value);
    return true;
  }

  /**
   * Append a header
   */
  static appendHeader(res: ServerResponse, name: string, value: string): void {
    // Validate header name
    if (!this.isValidHeaderName(name)) {
      throw new Error(`Invalid header name: ${name}`);
    }

    // Validate header value
    if (!this.isValidHeaderValue(value)) {
      throw new Error(`Invalid header value for '${name}': ${value}`);
    }

    res.appendHeader(name, value);
  }

  /**
   * Check if header name is valid
   */
  private static isValidHeaderName(name: string): boolean {
    // Header names must start with a letter and contain only alphanumeric characters and hyphens
    return /^[a-zA-Z][a-zA-Z0-9\-]*$/.test(name);
  }

  /**
   * Check if header value is valid
   */
  private static isValidHeaderValue(value: string): boolean {
    // Check for blocked patterns
    if (this.BLOCKED_HEADER_VALUES.some(pattern => pattern.test(value))) {
      return false;
    }

    // Check length
    if (value.length > 8192) {
      return false;
    }

    // Check for control characters (except tab and space)
    for (let i = 0; i < value.length; i++) {
      const charCode = value.charCodeAt(i);
      if (
        (charCode < 32 && charCode !== 9) || // Allow tab
        charCode === 127 // Delete
      ) {
        return false;
      }
    }

    return true;
  }

  /**
   * Sanitize header value
   */
  static sanitizeHeaderValue(value: string): string {
    // Remove blocked patterns
    let sanitized = value;
    for (const pattern of this.BLOCKED_HEADER_VALUES) {
      sanitized = sanitized.replace(pattern, '');
    }

    // Truncate if too long
    return sanitized.substring(0, 8192);
  }

  /**
   * Sanitize header name
   */
  static sanitizeHeaderName(name: string): string {
    // Remove non-alphanumeric characters except hyphens
    return name.replace(/[^a-zA-Z0-9\-]/g, '');
  }
}

// ============================================================================
// Response Headers Helper
// ============================================================================

export class ResponseHeaders {
  /**
   * Set multiple headers safely
   */
  static setHeaders(res: ServerResponse, headers: Record<string, string>): void {
    for (const [name, value] of Object.entries(headers)) {
      try {
        SafeHeaders.setHeader(res, name, value);
      } catch (error) {
        console.warn(`Failed to set header '${name}': ${error}`);
      }
    }
  }

  /**
   * Set common security headers
   */
  static setSecurityHeaders(res: ServerResponse): void {
    const securityHeaders = {
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'X-XSS-Protection': '1; mode=block',
      'Content-Security-Policy': "default-src 'self'",
    };

    this.setHeaders(res, securityHeaders);
  }

  /**
   * Set CORS headers safely
   */
  static setCORSHeaders(
    res: ServerResponse,
    origin: string,
    methods?: string[],
    headers?: string[]
  ): void {
    try {
      SafeHeaders.setHeader(res, 'Access-Control-Allow-Origin', origin);
      SafeHeaders.setHeader(
        res,
        'Access-Control-Allow-Methods',
        methods?.join(', ') || 'GET, POST, PUT, DELETE, OPTIONS'
      );
      SafeHeaders.setHeader(
        res,
        'Access-Control-Allow-Headers',
        headers?.join(', ') || 'Content-Type, Authorization'
      );
    } catch (error) {
      console.warn(`Failed to set CORS headers: ${error}`);
    }
  }

  /**
   * Set redirect header safely
   */
  static setRedirect(res: ServerResponse, url: string, status: number = 302): void {
    // Validate URL
    if (!url || url.length > 2048) {
      throw new Error('Invalid redirect URL');
    }

    // Sanitize URL
    const sanitizedUrl = url.replace(/[\r\n\t]/g, '');

    SafeHeaders.setHeader(res, 'Location', sanitizedUrl);
    res.statusCode = status;
  }
}
