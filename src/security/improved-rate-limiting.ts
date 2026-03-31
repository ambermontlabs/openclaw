/**
 * Improved rate limiting utilities.
 *
 * This module provides comprehensive rate limiting with support for
 * multiple strategies, sliding windows, and distributed scenarios.
 */

import { createHash } from "crypto";

// --------------------------------------------------------------------------
// Rate Limit Types
// --------------------------------------------------------------------------

/**
 * Rate limit strategy.
 */
export type RateLimitStrategy = "fixed-window" | "sliding-window" | "token-bucket";

/**
 * Rate limit options.
 */
export interface RateLimitOptions {
  /** Maximum number of requests allowed */
  maxRequests: number;
  /** Time window in milliseconds */
  windowMs: number;
  /** Strategy to use (default: sliding-window) */
  strategy?: RateLimitStrategy;
  /** Key to identify the client (default: ip) */
  key?: string;
  /** Custom error message */
  errorMessage?: string;
  /** Additional metadata to store with the request */
  metadata?: Record<string, unknown>;
}

/**
 * Rate limit result.
 */
export interface RateLimitResult {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Number of remaining requests in the window */
  remaining: number;
  /** Timestamp when the limit resets */
  resetTime: number;
  /** Retry after in milliseconds (if rate limited) */
  retryAfter?: number;
  /** Error message (if rate limited) */
  errorMessage?: string;
}

/**
 * Rate limit state.
 */
export interface RateLimitState {
  /** Current request count */
  count: number;
  /** Window start timestamp */
  windowStart: number;
  /** Last request timestamp */
  lastRequest?: number;
  /** Token bucket state (for token-bucket strategy) */
  tokens?: number;
}

// --------------------------------------------------------------------------
// Rate Limiter Base Class
// --------------------------------------------------------------------------

/**
 * Abstract base class for rate limiters.
 */
export abstract class RateLimiter {
  protected options: Required<RateLimitOptions>;

  constructor(options: RateLimitOptions) {
    this.options = {
      ...options,
      strategy: options.strategy || "sliding-window",
      errorMessage: options.errorMessage || "Rate limit exceeded",
    };
  }

  /**
   * Check if a request is allowed.
   */
  abstract check(key: string): RateLimitResult;

  /**
   * Record a request.
   */
  abstract record(key: string): void;

  /**
   * Get the current state for a key.
   */
  abstract getState(key: string): RateLimitState | null;

  /**
   * Reset the rate limit for a key.
   */
  abstract reset(key: string): void;

  /**
   * Get the remaining requests for a key.
   */
  getRemaining(key: string): number {
    const state = this.getState(key);
    if (!state) {
      return this.options.maxRequests;
    }

    const elapsed = Date.now() - state.windowStart;
    if (elapsed >= this.options.windowMs) {
      return this.options.maxRequests;
    }

    return Math.max(0, this.options.maxRequests - state.count);
  }
}

// --------------------------------------------------------------------------
// Fixed Window Rate Limiter
// --------------------------------------------------------------------------

/**
 * Fixed window rate limiter.
 */
export class FixedWindowRateLimiter extends RateLimiter {
  private windows: Map<string, { count: number; windowStart: number }>;

  constructor(options: RateLimitOptions) {
    super(options);
    this.windows = new Map();
  }

  check(key: string): RateLimitResult {
    const state = this.getState(key);

    if (!state) {
      return {
        allowed: true,
        remaining: this.options.maxRequests - 1,
        resetTime: Date.now() + this.options.windowMs,
      };
    }

    const elapsed = Date.now() - state.windowStart;

    if (elapsed >= this.options.windowMs) {
      // Window has expired, reset
      return {
        allowed: true,
        remaining: this.options.maxRequests - 1,
        resetTime: Date.now() + this.options.windowMs,
      };
    }

    if (state.count >= this.options.maxRequests) {
      return {
        allowed: false,
        remaining: 0,
        resetTime: state.windowStart + this.options.windowMs,
        retryAfter: (state.windowStart + this.options.windowMs) - Date.now(),
        errorMessage: this.options.errorMessage,
      };
    }

    return {
      allowed: true,
      remaining: this.options.maxRequests - state.count - 1,
      resetTime: state.windowStart + this.options.windowMs,
    };
  }

  record(key: string): void {
    const now = Date.now();
    let state = this.windows.get(key);

    if (!state || now - state.windowStart >= this.options.windowMs) {
      // Start new window
      state = { count: 1, windowStart: now };
    } else {
      // Increment count
      state.count += 1;
    }

    this.windows.set(key, state);
  }

  getState(key: string): RateLimitState | null {
    const state = this.windows.get(key);
    if (!state) {
      return null;
    }

    const elapsed = Date.now() - state.windowStart;
    if (elapsed >= this.options.windowMs) {
      return null; // Window expired
    }

    return {
      count: state.count,
      windowStart: state.windowStart,
    };
  }

  reset(key: string): void {
    this.windows.delete(key);
  }
}

// --------------------------------------------------------------------------
// Sliding Window Rate Limiter
// --------------------------------------------------------------------------

/**
 * Sliding window rate limiter.
 */
export class SlidingWindowRateLimiter extends RateLimiter {
  private requests: Map<string, number[]>; // key -> array of timestamps

  constructor(options: RateLimitOptions) {
    super(options);
    this.requests = new Map();
  }

  check(key: string): RateLimitResult {
    const timestamps = this.requests.get(key) || [];
    const now = Date.now();
    const windowStart = now - this.options.windowMs;

    // Filter out old timestamps
    const validTimestamps = timestamps.filter((ts) => ts > windowStart);

    if (validTimestamps.length >= this.options.maxRequests) {
      const oldestValid = validTimestamps[0];
      return {
        allowed: false,
        remaining: 0,
        resetTime: oldestValid + this.options.windowMs,
        retryAfter: (oldestValid + this.options.windowMs) - now,
        errorMessage: this.options.errorMessage,
      };
    }

    return {
      allowed: true,
      remaining: this.options.maxRequests - validTimestamps.length - 1,
      resetTime: now + this.options.windowMs,
    };
  }

  record(key: string): void {
    const now = Date.now();
    let timestamps = this.requests.get(key) || [];

    // Filter out old timestamps
    const windowStart = now - this.options.windowMs;
    timestamps = timestamps.filter((ts) => ts > windowStart);

    // Add new timestamp
    timestamps.push(now);

    this.requests.set(key, timestamps);
  }

  getState(key: string): RateLimitState | null {
    const timestamps = this.requests.get(key);
    if (!timestamps || timestamps.length === 0) {
      return null;
    }

    const now = Date.now();
    const windowStart = now - this.options.windowMs;
    const validTimestamps = timestamps.filter((ts) => ts > windowStart);

    if (validTimestamps.length === 0) {
      return null;
    }

    return {
      count: validTimestamps.length,
      windowStart: validTimestamps[0],
    };
  }

  reset(key: string): void {
    this.requests.delete(key);
  }
}

// --------------------------------------------------------------------------
// Token Bucket Rate Limiter
// --------------------------------------------------------------------------

/**
 * Token bucket rate limiter.
 */
export class TokenBucketRateLimiter extends RateLimiter {
  private buckets: Map<string, { tokens: number; lastRefill: number }>;

  constructor(options: RateLimitOptions) {
    super(options);
    this.buckets = new Map();

    // For token bucket, we need to adjust maxRequests to be the bucket capacity
    // and add a refill rate (tokens per second)
  }

  check(key: string): RateLimitResult {
    const now = Date.now();
    let state = this.buckets.get(key);

    if (!state) {
      // Initialize bucket
      state = { tokens: this.options.maxRequests, lastRefill: now };
    }

    // Refill tokens based on elapsed time
    const elapsed = (now - state.lastRefill) / 1000; // in seconds
    const refillRate = this.options.maxRequests / (this.options.windowMs / 1000);
    const tokensToAdd = elapsed * refillRate;
    
    state.tokens = Math.min(
      this.options.maxRequests,
      state.tokens + tokensToAdd
    );
    state.lastRefill = now;

    if (state.tokens < 1) {
      // Calculate time until next token
      const tokensNeeded = 1 - state.tokens;
      const timeToNextToken = tokensNeeded / refillRate * 1000; // in ms

      return {
        allowed: false,
        remaining: 0,
        resetTime: now + timeToNextToken,
        retryAfter: timeToNextToken,
        errorMessage: this.options.errorMessage,
      };
    }

    return {
      allowed: true,
      remaining: Math.floor(state.tokens - 1),
      resetTime: now + this.options.windowMs,
    };
  }

  record(key: string): void {
    const now = Date.now();
    let state = this.buckets.get(key);

    if (!state) {
      state = { tokens: this.options.maxRequests, lastRefill: now };
    }

    // Refill tokens
    const elapsed = (now - state.lastRefill) / 1000;
    const refillRate = this.options.maxRequests / (this.options.windowMs / 1000);
    state.tokens = Math.min(
      this.options.maxRequests,
      state.tokens + elapsed * refillRate
    );

    // Consume one token
    state.tokens = Math.max(0, state.tokens - 1);
    state.lastRefill = now;

    this.buckets.set(key, state);
  }

  getState(key: string): RateLimitState | null {
    const state = this.buckets.get(key);
    if (!state) {
      return null;
    }

    const now = Date.now();
    const elapsed = (now - state.lastRefill) / 1000;
    const refillRate = this.options.maxRequests / (this.options.windowMs / 1000);
    const currentTokens = Math.min(
      this.options.maxRequests,
      state.tokens + elapsed * refillRate
    );

    return {
      count: Math.floor(this.options.maxRequests - currentTokens),
      windowStart: state.lastRefill,
      tokens: Math.floor(currentTokens),
    };
  }

  reset(key: string): void {
    this.buckets.delete(key);
  }
}

// --------------------------------------------------------------------------
// Composite Rate Limiter
// --------------------------------------------------------------------------

/**
 * Composite rate limiter with multiple strategies.
 */
export class CompositeRateLimiter {
  private limiters: Map<string, RateLimiter>;

  constructor() {
    this.limiters = new Map();
  }

  /**
   * Add a rate limiter with a specific key.
   */
  addLimiter(key: string, limiter: RateLimiter): void {
    this.limiters.set(key, limiter);
  }

  /**
   * Check if a request is allowed across all limiters.
   */
  check(key: string): RateLimitResult {
    const limiter = this.limiters.get(key);
    if (!limiter) {
      return {
        allowed: true,
        remaining: Infinity,
        resetTime: 0,
      };
    }

    return limiter.check(key);
  }

  /**
   * Record a request for a specific limiter.
   */
  record(key: string): void {
    const limiter = this.limiters.get(key);
    if (limiter) {
      limiter.record(key);
    }
  }

  /**
   * Get the state for a specific limiter.
   */
  getState(key: string): RateLimitState | null {
    const limiter = this.limiters.get(key);
    if (!limiter) {
      return null;
    }

    return limiter.getState(key);
  }

  /**
   * Reset a specific limiter.
   */
  reset(key: string): void {
    const limiter = this.limiters.get(key);
    if (limiter) {
      limiter.reset(key);
    }
  }
}

// --------------------------------------------------------------------------
// Rate Limit Middleware
// --------------------------------------------------------------------------

/**
 * Express-style rate limit middleware.
 */
export function createRateLimitMiddleware(
  limiter: RateLimiter,
  options?: {
    keyExtractor?: (req: { ip?: string; url?: string }) => string;
  }
) {
  return (req: { ip?: string; url?: string }, res: { statusCode?: number }, next: (err?: Error) => void): void => {
    try {
      const key = options?.keyExtractor ? options.keyExtractor(req) : req.ip || "unknown";
      
      const result = limiter.check(key);

      if (!result.allowed) {
        res.statusCode = 429;
        res.setHeader("Retry-After", String(Math.ceil(result.retryAfter! / 1000)));
        res.setHeader("X-RateLimit-Limit", String(limiter.options.maxRequests));
        res.setHeader("X-RateLimit-Remaining", "0");
        res.setHeader("X-RateLimit-Reset", String(Math.floor(result.resetTime / 1000)));
        res.setHeader("X-RateLimit-Reset-After", String(Math.ceil(result.retryAfter! / 1000)));
        
        next(new Error(result.errorMessage || "Too Many Requests"));
        return;
      }

      limiter.record(key);

      res.setHeader("X-RateLimit-Limit", String(limiter.options.maxRequests));
      res.setHeader("X-RateLimit-Remaining", String(result.remaining));
      res.setHeader("X-RateLimit-Reset", String(Math.floor(result.resetTime / 1000)));

      next();
    } catch (error) {
      next(error as Error);
    }
  };
}

// --------------------------------------------------------------------------
// Distributed Rate Limiting
// --------------------------------------------------------------------------

/**
 * Distributed rate limiter for multi-server deployments.
 */
export class DistributedRateLimiter {
  private localLimiters: Map<string, RateLimiter>;
  private sharedState: Map<string, number>; // For distributed coordination

  constructor() {
    this.localLimiters = new Map();
    this.sharedState = new Map();
  }

  /**
   * Check if a request is allowed (distributed).
   */
  check(key: string, serverId: string): RateLimitResult {
    // In a real implementation, this would use Redis or similar
    // For now, we'll simulate distributed behavior
    
    const limiter = this.getOrCreateLimiter(key);
    return limiter.check(key);
  }

  /**
   * Record a request (distributed).
   */
  record(key: string, serverId: string): void {
    const limiter = this.getOrCreateLimiter(key);
    limiter.record(key);

    // In a real implementation, this would update shared state
  }

  private getOrCreateLimiter(key: string): RateLimiter {
    let limiter = this.localLimiters.get(key);
    
    if (!limiter) {
      limiter = new SlidingWindowRateLimiter({
        maxRequests: 100,
        windowMs: 60 * 1000, // 1 minute
      });
      this.localLimiters.set(key, limiter);
    }

    return limiter;
  }
}

// --------------------------------------------------------------------------
// Rate Limiting Utilities
// --------------------------------------------------------------------------

/**
 * Create a rate limiter from options.
 */
export function createRateLimiter(options: RateLimitOptions): RateLimiter {
  switch (options.strategy) {
    case "fixed-window":
      return new FixedWindowRateLimiter(options);
    case "sliding-window":
      return new SlidingWindowRateLimiter(options);
    case "token-bucket":
      return new TokenBucketRateLimiter(options);
    default:
      throw new Error(`Unknown rate limit strategy: ${options.strategy}`);
  }
}

/**
 * Create a rate limiter for authentication attempts.
 */
export function createAuthRateLimiter(options?: Partial<RateLimitOptions>): RateLimiter {
  return createRateLimiter({
    maxRequests: options?.maxRequests || 5,
    windowMs: options?.windowMs || 15 * 60 * 1000, // 15 minutes
    strategy: options?.strategy || "sliding-window",
    errorMessage: options?.errorMessage || "Too many authentication attempts. Please try again later.",
  });
}

/**
 * Create a rate limiter for API requests.
 */
export function createApiRateLimiter(options?: Partial<RateLimitOptions>): RateLimiter {
  return createRateLimiter({
    maxRequests: options?.maxRequests || 100,
    windowMs: options?.windowMs || 60 * 1000, // 1 minute
    strategy: options?.strategy || "sliding-window",
    errorMessage: options?.errorMessage || "API rate limit exceeded. Please try again later.",
  });
}
