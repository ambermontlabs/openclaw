/**
 * HTTP Security Headers Middleware.
 *
 * This module provides comprehensive security headers for HTTP responses
 * to protect against common web vulnerabilities.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

// --------------------------------------------------------------------------
// Security Headers Configuration
// --------------------------------------------------------------------------

/**
 * Security headers configuration options.
 */
export interface SecurityHeadersOptions {
  /** Enable Content-Security-Policy header (default: true) */
  contentSecurityPolicy?: boolean;
  /** Enable X-Content-Type-Options header (default: true) */
  contentTypeNosniff?: boolean;
  /** Enable X-Frame-Options header (default: true) */
  frameOptions?: boolean;
  /** Enable X-XSS-Protection header (default: true) */
  xssProtection?: boolean;
  /** Enable Strict-Transport-Security header (default: true) */
  strictTransportSecurity?: boolean;
  /** Enable Referrer-Policy header (default: true) */
  referrerPolicy?: boolean;
  /** Enable Permissions-Policy header (default: true) */
  permissionsPolicy?: boolean;
  /** Enable Cache-Control header for sensitive data (default: true) */
  noCache?: boolean;
  /** Custom Content-Security-Policy directives */
  contentSecurityPolicyDirectives?: string[];
}

/**
 * Default security headers configuration.
 */
const DEFAULT_OPTIONS: Required<SecurityHeadersOptions> = {
  contentSecurityPolicy: true,
  contentTypeNosniff: true,
  frameOptions: true,
  xssProtection: true,
  strictTransportSecurity: true,
  referrerPolicy: true,
  permissionsPolicy: true,
  noCache: true,
  contentSecurityPolicyDirectives: [],
};

/**
 * Generate Content-Security-Policy header value.
 */
function generateContentSecurityPolicy(directives: string[]): string {
  const baseDirectives = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https:",
    "font-src 'self'",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ];

  return [...baseDirectives, ...directives].join("; ");
}

/**
 * Generate Strict-Transport-Security header value.
 */
function generateStrictTransportSecurity(): string {
  return "max-age=31536000; includeSubDomains; preload";
}

/**
 * Generate Referrer-Policy header value.
 */
function generateReferrerPolicy(): string {
  return "strict-origin-when-cross-origin";
}

/**
 * Generate Permissions-Policy header value.
 */
function generatePermissionsPolicy(): string {
  return [
    "geolocation=()",
    "microphone=()",
    "camera=()",
    "payment=()",
    "usb=()",
    "magnetometer=()",
    "gyroscope=()",
    "accelerometer=()",
  ].join(", ");
}

// --------------------------------------------------------------------------
// Security Headers Middleware
// --------------------------------------------------------------------------

/**
 * Add security headers to the response.
 */
export function addSecurityHeaders(
  res: ServerResponse,
  options?: SecurityHeadersOptions
): void {
  const config = { ...DEFAULT_OPTIONS, ...options };

  // Content-Security-Policy
  if (config.contentSecurityPolicy) {
    const csp = generateContentSecurityPolicy(
      config.contentSecurityPolicyDirectives || []
    );
    res.setHeader("Content-Security-Policy", csp);
  }

  // X-Content-Type-Options
  if (config.contentTypeNosniff) {
    res.setHeader("X-Content-Type-Options", "nosniff");
  }

  // X-Frame-Options
  if (config.frameOptions) {
    res.setHeader("X-Frame-Options", "DENY");
  }

  // X-XSS-Protection (legacy but still useful)
  if (config.xssProtection) {
    res.setHeader("X-XSS-Protection", "1; mode=block");
  }

  // Strict-Transport-Security
  if (config.strictTransportSecurity) {
    res.setHeader("Strict-Transport-Security", generateStrictTransportSecurity());
  }

  // Referrer-Policy
  if (config.referrerPolicy) {
    res.setHeader("Referrer-Policy", generateReferrerPolicy());
  }

  // Permissions-Policy
  if (config.permissionsPolicy) {
    res.setHeader("Permissions-Policy", generatePermissionsPolicy());
  }

  // Cache-Control for sensitive data
  if (config.noCache) {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
  }
}

/**
 * Express-style middleware for security headers.
 */
export function securityHeadersMiddleware(
  req: IncomingMessage,
  res: ServerResponse,
  next: (err?: Error) => void
): void {
  try {
    addSecurityHeaders(res);
    next();
  } catch (error) {
    next(error as Error);
  }
}

/**
 * Koa-style middleware for security headers.
 */
export function createSecurityHeadersMiddleware(options?: SecurityHeadersOptions) {
  return async (ctx: { res: ServerResponse }, next: () => Promise<void>) => {
    addSecurityHeaders(ctx.res, options);
    await next();
  };
}

// --------------------------------------------------------------------------
// CORS Security
// --------------------------------------------------------------------------

/**
 * CORS security configuration.
 */
export interface CorsSecurityOptions {
  /** Allowed origins (default: only same origin) */
  allowedOrigins?: string[];
  /** Allow credentials (default: false) */
  allowCredentials?: boolean;
  /** Allowed methods (default: GET, POST, PUT, DELETE) */
  allowedMethods?: string[];
  /** Allowed headers (default: *) */
  allowedHeaders?: string[];
  /** Max age (default: 86400) */
  maxAge?: number;
}

/**
 * Generate CORS headers securely.
 */
export function generateCorsHeaders(
  req: IncomingMessage,
  options?: CorsSecurityOptions
): Record<string, string> {
  const config = {
    allowedOrigins: ["*"],
    allowCredentials: false,
    allowedMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["*"],
    maxAge: 86400,
    ...options,
  };

  const headers: Record<string, string> = {};

  // Determine allowed origin
  if (config.allowedOrigins.length === 0) {
    headers["Access-Control-Allow-Origin"] = "none";
  } else if (config.allowedOrigins.length === 1 && config.allowedOrigins[0] === "*") {
    headers["Access-Control-Allow-Origin"] = "*";
  } else if (req.headers.origin && config.allowedOrigins.includes(req.headers.origin)) {
    headers["Access-Control-Allow-Origin"] = req.headers.origin;
  } else {
    headers["Access-Control-Allow-Origin"] = "none";
  }

  // Allow credentials
  if (config.allowCredentials) {
    headers["Access-Control-Allow-Credentials"] = "true";
  }

  // Allow methods
  if (config.allowedMethods.length > 0) {
    headers["Access-Control-Allow-Methods"] = config.allowedMethods.join(", ");
  }

  // Allow headers
  if (config.allowedHeaders.length > 0) {
    headers["Access-Control-Allow-Headers"] = config.allowedHeaders.join(", ");
  }

  // Max age
  headers["Access-Control-Max-Age"] = String(config.maxAge);

  return headers;
}

/**
 * Add CORS headers to response securely.
 */
export function addCorsHeaders(
  res: ServerResponse,
  req?: IncomingMessage,
  options?: CorsSecurityOptions
): void {
  const headers = generateCorsHeaders(req || null, options);
  for (const [key, value] of Object.entries(headers)) {
    res.setHeader(key, value);
  }
}

// --------------------------------------------------------------------------
// Security Headers for Gateway
// --------------------------------------------------------------------------

/**
 * Add security headers specifically for the OpenClaw gateway.
 */
export function addGatewaySecurityHeaders(
  res: ServerResponse,
  options?: SecurityHeadersOptions
): void {
  // Add standard security headers
  addSecurityHeaders(res, options);

  // Gateway-specific headers
  res.setHeader("X-OpenClaw-Version", process.env.OPENCLAW_VERSION || "unknown");
  res.setHeader("X-Request-ID", generateRequestId());
}

/**
 * Generate a unique request ID.
 */
export function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
}
