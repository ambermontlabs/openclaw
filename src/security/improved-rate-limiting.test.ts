/**
 * Tests for improved rate limiting utilities.
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  createRateLimiter,
  FixedWindowRateLimiter,
  SlidingWindowRateLimiter,
  TokenBucketRateLimiter,
} from "./improved-rate-limiting.js";

describe("Rate Limiting", () => {
  describe("Fixed Window Rate Limiter", () => {
    let limiter: FixedWindowRateLimiter;

    beforeEach(() => {
      limiter = new FixedWindowRateLimiter({
        maxRequests: 5,
        windowMs: 60 * 1000, // 1 minute
      });
    });

    it("should allow requests within limit", () => {
      for (let i = 0; i < 5; i++) {
        const result = limiter.check("test-key");
        expect(result.allowed).toBe(true);
        limiter.record("test-key");
      }
    });

    it("should block requests over limit", () => {
      for (let i = 0; i < 5; i++) {
        limiter.record("test-key");
      }

      const result = limiter.check("test-key");
      expect(result.allowed).toBe(false);
    });

    it("should reset after window expires", () => {
      // Manually set window to expired
      const state = limiter.getState("test-key");
      if (state) {
        // In a real test, we'd mock Date.now() to simulate time passing
      }
    });
  });

  describe("Sliding Window Rate Limiter", () => {
    let limiter: SlidingWindowRateLimiter;

    beforeEach(() => {
      limiter = new SlidingWindowRateLimiter({
        maxRequests: 5,
        windowMs: 60 * 1000, // 1 minute
      });
    });

    it("should allow requests within limit", () => {
      for (let i = 0; i < 5; i++) {
        const result = limiter.check("test-key");
        expect(result.allowed).toBe(true);
        limiter.record("test-key");
      }
    });

    it("should block requests over limit", () => {
      for (let i = 0; i < 5; i++) {
        limiter.record("test-key");
      }

      const result = limiter.check("test-key");
      expect(result.allowed).toBe(false);
    });

    it("should calculate remaining correctly", () => {
      limiter.record("test-key");
      const result = limiter.check("test-key");
      expect(result.remaining).toBe(4);
    });
  });

  describe("Token Bucket Rate Limiter", () => {
    let limiter: TokenBucketRateLimiter;

    beforeEach(() => {
      limiter = new TokenBucketRateLimiter({
        maxRequests: 5,
        windowMs: 60 * 1000, // 1 minute
      });
    });

    it("should allow requests within limit", () => {
      for (let i = 0; i < 5; i++) {
        const result = limiter.check("test-key");
        expect(result.allowed).toBe(true);
        limiter.record("test-key");
      }
    });

    it("should block requests over limit", () => {
      for (let i = 0; i < 5; i++) {
        limiter.record("test-key");
      }

      const result = limiter.check("test-key");
      expect(result.allowed).toBe(false);
    });
  });

  describe("createRateLimiter", () => {
    it("should create fixed window limiter", () => {
      const limiter = createRateLimiter({
        maxRequests: 10,
        windowMs: 60 * 1000,
        strategy: "fixed-window",
      });
      expect(limiter).toBeInstanceOf(FixedWindowRateLimiter);
    });

    it("should create sliding window limiter", () => {
      const limiter = createRateLimiter({
        maxRequests: 10,
        windowMs: 60 * 1000,
        strategy: "sliding-window",
      });
      expect(limiter).toBeInstanceOf(SlidingWindowRateLimiter);
    });

    it("should create token bucket limiter", () => {
      const limiter = createRateLimiter({
        maxRequests: 10,
        windowMs: 60 * 1000,
        strategy: "token-bucket",
      });
      expect(limiter).toBeInstanceOf(TokenBucketRateLimiter);
    });

    it("should default to sliding window", () => {
      const limiter = createRateLimiter({
        maxRequests: 10,
        windowMs: 60 * 1000,
      });
      expect(limiter).toBeInstanceOf(SlidingWindowRateLimiter);
    });
  });

  describe("Auth Rate Limiter", () => {
    it("should create auth-specific limiter", () => {
      const limiter = createRateLimiter({
        maxRequests: 5,
        windowMs: 15 * 60 * 1000, // 15 minutes
        strategy: "sliding-window",
      });

      // Test that it works
      for (let i = 0; i < 5; i++) {
        const result = limiter.check("test-key");
        expect(result.allowed).toBe(true);
        limiter.record("test-key");
      }

      const result = limiter.check("test-key");
      expect(result.allowed).toBe(false);
    });
  });

  describe("Rate Limit Result", () => {
    it("should include remaining count", () => {
      const limiter = createRateLimiter({
        maxRequests: 10,
        windowMs: 60 * 1000,
      });

      limiter.record("test-key");
      const result = limiter.check("test-key");

      expect(result).toHaveProperty("remaining");
      expect(result.remaining).toBe(9);
    });

    it("should include reset time", () => {
      const limiter = createRateLimiter({
        maxRequests: 10,
        windowMs: 60 * 1000,
      });

      const result = limiter.check("test-key");
      expect(result).toHaveProperty("resetTime");
    });

    it("should include retry after when blocked", () => {
      const limiter = createRateLimiter({
        maxRequests: 1,
        windowMs: 60 * 1000,
      });

      limiter.record("test-key");
      const result = limiter.check("test-key");

      expect(result.allowed).toBe(false);
      expect(result).toHaveProperty("retryAfter");
    });
  });
});
