/**
 * Safe Logging for OpenCLAW
 * Prevents log injection attacks
 */

// ============================================================================
// Safe Logger Class
// ============================================================================

export class SafeLogger {
  private static readonly MAX_LOG_LENGTH = 10000;
  private static readonly BLOCKED_PATTERNS = [
    /\r/, // CR
    /\n/, // LF
    /\0/, // Null byte
  ];

  /**
   * Log a message with sanitized values
   */
  static log(message: string, ...args: unknown[]): void {
    const sanitizedArgs = args.map(arg => this.sanitizeLogValue(arg));
    console.log(message, ...sanitizedArgs);
  }

  /**
   * Log an info message
   */
  static info(message: string, ...args: unknown[]): void {
    const sanitizedArgs = args.map(arg => this.sanitizeLogValue(arg));
    console.info(message, ...sanitizedArgs);
  }

  /**
   * Log a warning message
   */
  static warn(message: string, ...args: unknown[]): void {
    const sanitizedArgs = args.map(arg => this.sanitizeLogValue(arg));
    console.warn(message, ...sanitizedArgs);
  }

  /**
   * Log an error message
   */
  static error(message: string, ...args: unknown[]): void {
    const sanitizedArgs = args.map(arg => this.sanitizeLogValue(arg));
    console.error(message, ...sanitizedArgs);
  }

  /**
   * Log a debug message
   */
  static debug(message: string, ...args: unknown[]): void {
    const sanitizedArgs = args.map(arg => this.sanitizeLogValue(arg));
    console.debug(message, ...sanitizedArgs);
  }

  /**
   * Sanitize a log value
   */
  private static sanitizeLogValue(value: unknown): string {
    if (typeof value !== 'string') {
      return JSON.stringify(value);
    }

    // Remove blocked patterns
    let sanitized = value;
    for (const pattern of this.BLOCKED_PATTERNS) {
      sanitized = sanitized.replace(pattern, '');
    }

    // Truncate if too long
    return sanitized.substring(0, this.MAX_LOG_LENGTH);
  }

  /**
   * Sanitize a log message
   */
  static sanitizeMessage(message: string): string {
    // Remove blocked patterns
    let sanitized = message;
    for (const pattern of this.BLOCKED_PATTERNS) {
      sanitized = sanitized.replace(pattern, '');
    }

    // Truncate if too long
    return sanitized.substring(0, this.MAX_LOG_LENGTH);
  }
}

// ============================================================================
// Structured Logger
// ============================================================================

export interface LogEntry {
  timestamp: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  message: string;
  context?: Record<string, unknown>;
}

export class StructuredLogger {
  private static readonly MAX_CONTEXT_KEYS = 10;
  private static readonly MAX_CONTEXT_KEY_LENGTH = 64;
  private static readonly MAX_CONTEXT_VALUE_LENGTH = 1024;

  /**
   * Log a structured entry
   */
  static log(entry: LogEntry): void {
    const sanitizedEntry = this.sanitizeLogEntry(entry);
    console.log(JSON.stringify(sanitizedEntry));
  }

  /**
   * Sanitize a log entry
   */
  private static sanitizeLogEntry(entry: LogEntry): LogEntry {
    const sanitizedContext = this.sanitizeContext(entry.context);

    return {
      timestamp: entry.timestamp,
      level: entry.level,
      message: SafeLogger.sanitizeMessage(entry.message),
      context: sanitizedContext,
    };
  }

  /**
   * Sanitize context object
   */
  private static sanitizeContext(
    context?: Record<string, unknown>
  ): Record<string, string> | undefined {
    if (!context) {
      return undefined;
    }

    const sanitized: Record<string, string> = {};

    let keyCount = 0;
    for (const [key, value] of Object.entries(context)) {
      if (keyCount >= this.MAX_CONTEXT_KEYS) {
        break;
      }

      // Sanitize key
      const sanitizedKey = this.sanitizeContextKey(key);
      if (!sanitizedKey) {
        continue;
      }

      // Sanitize value
      const sanitizedValue = this.sanitizeContextValue(value);

      sanitized[sanitizedKey] = sanitizedValue;
      keyCount++;
    }

    return sanitized;
  }

  /**
   * Sanitize context key
   */
  private static sanitizeContextKey(key: string): string | null {
    // Remove non-alphanumeric characters except hyphens and underscores
    let sanitized = key.replace(/[^a-zA-Z0-9\-_]/g, '');

    // Truncate if too long
    sanitized = sanitized.substring(0, this.MAX_CONTEXT_KEY_LENGTH);

    return sanitized || null;
  }

  /**
   * Sanitize context value
   */
  private static sanitizeContextValue(value: unknown): string {
    if (typeof value !== 'string') {
      return JSON.stringify(value);
    }

    // Remove blocked patterns
    let sanitized = value;
    for (const pattern of SafeLogger.BLOCKED_PATTERNS) {
      sanitized = sanitized.replace(pattern, '');
    }

    // Truncate if too long
    return sanitized.substring(0, this.MAX_CONTEXT_VALUE_LENGTH);
  }

  /**
   * Log an info entry
   */
  static info(message: string, context?: Record<string, unknown>): void {
    this.log({
      timestamp: new Date().toISOString(),
      level: 'info',
      message,
      context,
    });
  }

  /**
   * Log a warn entry
   */
  static warn(message: string, context?: Record<string, unknown>): void {
    this.log({
      timestamp: new Date().toISOString(),
      level: 'warn',
      message,
      context,
    });
  }

  /**
   * Log an error entry
   */
  static error(message: string, context?: Record<string, unknown>): void {
    this.log({
      timestamp: new Date().toISOString(),
      level: 'error',
      message,
      context,
    });
  }

  /**
   * Log a debug entry
   */
  static debug(message: string, context?: Record<string, unknown>): void {
    this.log({
      timestamp: new Date().toISOString(),
      level: 'debug',
      message,
      context,
    });
  }
}

// ============================================================================
// Audit Logger
// ============================================================================

export interface AuditEntry {
  timestamp: string;
  type: string;
  action: string;
  user?: string;
  resource?: string;
  result: 'success' | 'failure';
  details?: Record<string, unknown>;
}

export class AuditLogger {
  private static readonly AUDIT_LOG: AuditEntry[] = [];

  /**
   * Log an audit entry
   */
  static log(entry: AuditEntry): void {
    const sanitizedEntry = this.sanitizeAuditEntry(entry);
    this.AUDIT_LOG.push(sanitizedEntry);

    // Keep only last 1000 entries
    if (this.AUDIT_LOG.length > 1000) {
      this.AUDIT_LOG.shift();
    }

    // Log to console
    console.log(`AUDIT: ${JSON.stringify(sanitizedEntry)}`);
  }

  /**
   * Sanitize an audit entry
   */
  private static sanitizeAuditEntry(entry: AuditEntry): AuditEntry {
    const sanitizedDetails = StructuredLogger.sanitizeContext(entry.details);

    return {
      timestamp: entry.timestamp,
      type: StructuredLogger.sanitizeContextKey(entry.type) || 'unknown',
      action: StructuredLogger.sanitizeMessage(entry.action),
      user: entry.user ? StructuredLogger.sanitizeContextKey(entry.user) : undefined,
      resource: entry.resource ? StructuredLogger.sanitizeMessage(entry.resource) : undefined,
      result: entry.result,
      details: sanitizedDetails,
    };
  }

  /**
   * Get audit log
   */
  static getAuditLog(): AuditEntry[] {
    return this.AUDIT_LOG;
  }

  /**
   * Clear audit log
   */
  static clearAuditLog(): void {
    this.AUDIT_LOG.length = 0;
  }

  /**
   * Log a command execution audit
   */
  static logCommandExecution(
    command: string,
    args: string[],
    valid: boolean,
    errors?: string[]
  ): void {
    this.log({
      timestamp: new Date().toISOString(),
      type: 'command_execution',
      action: command,
      result: valid ? 'success' : 'failure',
      details: {
        args: args.map(a => a.length > 50 ? `${a.substring(0, 50)}...` : a),
        errors: errors?.length ? errors : undefined,
      },
    });
  }

  /**
   * Log a path access audit
   */
  static logPathAccess(
    userPath: string,
    baseDir: string,
    valid: boolean,
    errors?: string[]
  ): void {
    this.log({
      timestamp: new Date().toISOString(),
      type: 'path_access',
      action: userPath,
      result: valid ? 'success' : 'failure',
      details: {
        baseDir,
        errors: errors?.length ? errors : undefined,
      },
    });
  }
}
