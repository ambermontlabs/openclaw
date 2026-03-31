/**
 * Comprehensive audit logging system.
 *
 * This module provides structured, secure logging for security events
 * including authentication, authorization, and sensitive operations.
 */

import type { IncomingMessage } from "node:http";

// --------------------------------------------------------------------------
// Audit Event Types
// --------------------------------------------------------------------------

/**
 * Audit event severity levels.
 */
export type AuditSeverity = "info" | "warn" | "error" | "critical";

/**
 * Audit event categories.
 */
export type AuditCategory =
  | "authentication"
  | "authorization"
  | "configuration"
  | "file_access"
  | "network"
  | "command_execution"
  | "secrets"
  | "system"
  | "user_action";

/**
 * Audit event structure.
 */
export interface AuditEvent {
  /** Event timestamp in ISO format */
  timestamp: string;
  /** Unique event ID */
  eventId: string;
  /** Severity level */
  severity: AuditSeverity;
  /** Event category */
  category: AuditCategory;
  /** Event action */
  action: string;
  /** Description of the event */
  description: string;
  /** User ID (if applicable) */
  userId?: string;
  /** IP address of the requester */
  ipAddress?: string;
  /** User agent (if applicable) */
  userAgent?: string;
  /** Additional context data (will be redacted for secrets) */
  context?: Record<string, unknown>;
  /** Whether the event was successful */
  success: boolean;
  /** Error message (if applicable) */
  errorMessage?: string;
}

/**
 * Audit log entry with metadata.
 */
export interface AuditLogEntry {
  /** Log entry ID */
  id: string;
  /** Event data */
  event: AuditEvent;
  /** Log source */
  source: string;
  /** Redacted context (for safe logging) */
  redactedContext?: Record<string, unknown>;
}

// --------------------------------------------------------------------------
// Audit Logger
// --------------------------------------------------------------------------

/**
 * Audit logger options.
 */
export interface AuditLoggerOptions {
  /** Enable audit logging (default: true) */
  enabled?: boolean;
  /** Log level threshold (events with this severity or higher will be logged) */
  minSeverity?: AuditSeverity;
  /** Include stack traces in logs (default: false for security) */
  includeStackTraces?: boolean;
  /** Custom context to add to all events */
  defaultContext?: Record<string, unknown>;
}

/**
 * Default audit logger options.
 */
const DEFAULT_AUDIT_OPTIONS: Required<AuditLoggerOptions> = {
  enabled: true,
  minSeverity: "info",
  includeStackTraces: false,
  defaultContext: {},
};

/**
 * Audit logger class.
 */
export class AuditLogger {
  private options: Required<AuditLoggerOptions>;
  private source: string;

  constructor(source: string, options?: AuditLoggerOptions) {
    this.source = source;
    this.options = { ...DEFAULT_AUDIT_OPTIONS, ...options };
  }

  /**
   * Log an audit event.
   */
  log(event: AuditEvent): void {
    if (!this.options.enabled) {
      return;
    }

    // Check severity threshold
    if (this.getSeverityLevel(event.severity) < this.getSeverityLevel(this.options.minSeverity)) {
      return;
    }

    // Create log entry
    const entry: AuditLogEntry = {
      id: this.generateEventId(),
      event,
      source: this.source,
    };

    // Redact context for safe logging
    entry.redactedContext = this.redactContext(event.context);

    // Format and output the log
    const formatted = this.formatEntry(entry);
    this.output(formatted, event.severity);
  }

  /**
   * Log an authentication attempt.
   */
  logAuthentication(
    userId: string,
    success: boolean,
    options?: {
      ipAddress?: string;
      userAgent?: string;
      method?: string;
      errorMessage?: string;
    }
  ): void {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      eventId: this.generateEventId(),
      severity: success ? "info" : "warn",
      category: "authentication",
      action: options?.method || "login",
      description: success
        ? `Authentication successful for user ${userId}`
        : `Authentication failed for user ${userId}`,
      userId,
      ipAddress: options?.ipAddress,
      userAgent: options?.userAgent,
      context: {
        method: options?.method,
      },
      success,
      errorMessage: options?.errorMessage,
    };

    this.log(event);
  }

  /**
   * Log an authorization decision.
   */
  logAuthorization(
    userId: string,
    resource: string,
    action: string,
    allowed: boolean,
    options?: {
      ipAddress?: string;
      context?: Record<string, unknown>;
    }
  ): void {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      eventId: this.generateEventId(),
      severity: allowed ? "info" : "warn",
      category: "authorization",
      action,
      description: allowed
        ? `Authorization granted for user ${userId} to access ${resource}`
        : `Authorization denied for user ${userId} to access ${resource}`,
      userId,
      ipAddress: options?.ipAddress,
      context: {
        resource,
        ...options?.context,
      },
      success: allowed,
    };

    this.log(event);
  }

  /**
   * Log a configuration change.
   */
  logConfiguration(
    userId: string,
    action: string,
    resource: string,
    options?: {
      ipAddress?: string;
      changes?: Record<string, unknown>;
    }
  ): void {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      eventId: this.generateEventId(),
      severity: "info",
      category: "configuration",
      action,
      description: `Configuration ${action} for resource ${resource}`,
      userId,
      ipAddress: options?.ipAddress,
      context: {
        resource,
        changes: options?.changes,
      },
      success: true,
    };

    this.log(event);
  }

  /**
   * Log a file access event.
   */
  logFileAccess(
    userId: string,
    filePath: string,
    action: string,
    success: boolean,
    options?: {
      ipAddress?: string;
      fileSize?: number;
    }
  ): void {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      eventId: this.generateEventId(),
      severity: success ? "info" : "warn",
      category: "file_access",
      action,
      description: `File ${action} for path ${filePath}`,
      userId,
      ipAddress: options?.ipAddress,
      context: {
        filePath,
        fileSize: options?.fileSize,
      },
      success,
    };

    this.log(event);
  }

  /**
   * Log a network event.
   */
  logNetwork(
    userId: string,
    action: string,
    host: string,
    success: boolean,
    options?: {
      ipAddress?: string;
      port?: number;
      protocol?: string;
    }
  ): void {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      eventId: this.generateEventId(),
      severity: success ? "info" : "warn",
      category: "network",
      action,
      description: `Network ${action} to host ${host}`,
      userId,
      ipAddress: options?.ipAddress,
      context: {
        host,
        port: options?.port,
        protocol: options?.protocol,
      },
      success,
    };

    this.log(event);
  }

  /**
   * Log a command execution event.
   */
  logCommandExecution(
    userId: string,
    command: string,
    success: boolean,
    options?: {
      ipAddress?: string;
      cwd?: string;
      durationMs?: number;
      exitCode?: number;
    }
  ): void {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      eventId: this.generateEventId(),
      severity: success ? "info" : "error",
      category: "command_execution",
      action: "execute",
      description: `Command execution ${success ? "completed" : "failed"}`,
      userId,
      ipAddress: options?.ipAddress,
      context: {
        command: this.redactCommand(command),
        cwd: options?.cwd,
        durationMs: options?.durationMs,
        exitCode: options?.exitCode,
      },
      success,
    };

    this.log(event);
  }

  /**
   * Log a secrets-related event.
   */
  logSecrets(
    userId: string,
    action: string,
    success: boolean,
    options?: {
      ipAddress?: string;
      secretType?: string;
    }
  ): void {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      eventId: this.generateEventId(),
      severity: success ? "info" : "error",
      category: "secrets",
      action,
      description: `Secrets ${action}`,
      userId,
      ipAddress: options?.ipAddress,
      context: {
        secretType: options?.secretType,
      },
      success,
    };

    this.log(event);
  }

  /**
   * Log a system event.
   */
  logSystem(
    action: string,
    success: boolean,
    options?: {
      ipAddress?: string;
      details?: Record<string, unknown>;
    }
  ): void {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      eventId: this.generateEventId(),
      severity: success ? "info" : "error",
      category: "system",
      action,
      description: `System ${action}`,
      ipAddress: options?.ipAddress,
      context: {
        ...options?.details,
      },
      success,
    };

    this.log(event);
  }

  /**
   * Log a user action.
   */
  logUserAction(
    userId: string,
    action: string,
    success: boolean,
    options?: {
      ipAddress?: string;
      details?: Record<string, unknown>;
    }
  ): void {
    const event: AuditEvent = {
      timestamp: new Date().toISOString(),
      eventId: this.generateEventId(),
      severity: success ? "info" : "warn",
      category: "user_action",
      action,
      description: `User ${action}`,
      userId,
      ipAddress: options?.ipAddress,
      context: {
        ...options?.details,
      },
      success,
    };

    this.log(event);
  }

  /**
   * Extract request information from an HTTP request.
   */
  extractRequestInfo(req: IncomingMessage): {
    ipAddress?: string;
    userAgent?: string;
  } {
    const headers = req.headers;

    return {
      ipAddress: this.extractIpAddress(headers),
      userAgent: headers["user-agent"] as string | undefined,
    };
  }

  /**
   * Extract IP address from request headers.
   */
  extractIpAddress(headers: IncomingMessage["headers"]): string | undefined {
    // Check for forwarded headers first
    if (headers["x-forwarded-for"]) {
      const forwarded = headers["x-forwarded-for"] as string;
      // Take the first IP in the chain (original client)
      return forwarded.split(",")[0]?.trim();
    }

    if (headers["x-real-ip"]) {
      return headers["x-real-ip"] as string;
    }

    // Fall back to socket remote address
    if (req.socket) {
      return req.socket.remoteAddress as string;
    }

    return undefined;
  }

  /**
   * Generate a unique event ID.
   */
  generateEventId(): string {
    return `evt_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  }

  /**
   * Get numeric severity level for comparison.
   */
  getSeverityLevel(severity: AuditSeverity): number {
    const levels: Record<AuditSeverity, number> = {
      info: 0,
      warn: 1,
      error: 2,
      critical: 3,
    };
    return levels[severity];
  }

  /**
   * Redact context for safe logging.
   */
  redactContext(context?: Record<string, unknown>): Record<string, unknown> | undefined {
    if (!context) {
      return undefined;
    }

    const redacted: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(context)) {
      // Don't redact certain keys
      if (
        key.toLowerCase().includes("id") ||
        key.toLowerCase().includes("name") ||
        key.toLowerCase().includes("timestamp")
      ) {
        redacted[key] = value;
      } else if (typeof value === "string") {
        // Redact strings
        redacted[key] = this.redactSecretsInString(value);
      } else if (typeof value === "object" && value !== null) {
        // Recursively redact objects
        redacted[key] = this.redactContext(value as Record<string, unknown>);
      } else {
        redacted[key] = value;
      }
    }

    return redacted;
  }

  /**
   * Redact secrets in a string.
   */
  redactSecretsInString(input: string): string {
    // Simple implementation - can be enhanced with the secrets-management module
    const secretPatterns = [
      /(?:password|secret|token)[=:\s]+[^\s]*/gi,
      /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    ];

    let result = input;
    for (const pattern of secretPatterns) {
      result = result.replace(pattern, "[REDACTED]");
    }

    return result;
  }

  /**
   * Redact command for safe logging.
   */
  redactCommand(command: string): string {
    // Redact common secret patterns in commands
    const redacted = command.replace(
      /(?:password|secret|token)[=:\s]+[^\s]*/gi,
      "$1=[REDACTED]"
    );

    return redacted;
  }

  /**
   * Format an audit log entry.
   */
  formatEntry(entry: AuditLogEntry): string {
    const { event, id, source } = entry;

    const parts: string[] = [
      `[${event.timestamp}]`,
      `[${id}]`,
      `[${source}]`,
      `[${event.severity.toUpperCase()}]`,
      `[${event.category}]`,
      `[${event.action}]`,
      event.description,
    ];

    if (entry.redactedContext && Object.keys(entry.redactedContext).length > 0) {
      parts.push(`[context=${JSON.stringify(entry.redactedContext)}]`);
    }

    if (event.userId) {
      parts.push(`[user=${event.userId}]`);
    }

    if (event.ipAddress) {
      parts.push(`[ip=${event.ipAddress}]`);
    }

    if (event.errorMessage) {
      parts.push(`[error=${this.redactSecretsInString(event.errorMessage)}]`);
    }

    return parts.join(" ");
  }

  /**
   * Output a formatted log entry.
   */
  output(formatted: string, severity: AuditSeverity): void {
    // Use console methods to avoid circular dependencies
    switch (severity) {
      case "critical":
        console.error(formatted);
        break;
      case "error":
        console.error(formatted);
        break;
      case "warn":
        console.warn(formatted);
        break;
      case "info":
        console.log(formatted);
        break;
    }
  }

  /**
   * Create an audit event from request information.
   */
  createEventFromRequest(
    category: AuditCategory,
    action: string,
    success: boolean,
    req?: IncomingMessage,
    options?: {
      description?: string;
      context?: Record<string, unknown>;
      errorMessage?: string;
    }
  ): AuditEvent {
    const requestInfo = req ? this.extractRequestInfo(req) : {};

    return {
      timestamp: new Date().toISOString(),
      eventId: this.generateEventId(),
      severity: success ? "info" : "warn",
      category,
      action,
      description:
        options?.description ||
        `${category.replace("_", " ").toUpperCase()} ${action}`,
      userId: requestInfo.ipAddress, // Use IP as user ID if no user
      ipAddress: requestInfo.ipAddress,
      userAgent: requestInfo.userAgent,
      context: {
        ...this.options.defaultContext,
        ...options?.context,
      },
      success,
      errorMessage: options?.errorMessage,
    };
  }
}

// --------------------------------------------------------------------------
// Global Audit Logger
// --------------------------------------------------------------------------

/**
 * Global audit logger instance.
 */
let globalAuditLogger: AuditLogger | null = null;

/**
 * Initialize the global audit logger.
 */
export function initGlobalAuditLogger(source: string, options?: AuditLoggerOptions): void {
  globalAuditLogger = new AuditLogger(source, options);
}

/**
 * Get the global audit logger.
 */
export function getGlobalAuditLogger(): AuditLogger | null {
  return globalAuditLogger;
}

/**
 * Log an event using the global audit logger.
 */
export function logGlobalEvent(event: AuditEvent): void {
  if (globalAuditLogger) {
    globalAuditLogger.log(event);
  }
}
