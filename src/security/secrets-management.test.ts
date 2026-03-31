/**
 * Tests for secrets management utilities.
 */

import { describe, it, expect } from "vitest";
import {
  containsSecrets,
  redactSecrets,
  validateSecret,
  generateSecureSecret,
} from "./secrets-management.js";

describe("Secrets Management", () => {
  describe("containsSecrets", () => {
    it("should detect API key pattern", () => {
      expect(containsSecrets("api_key=sk_live_1234567890abcdef")).toBe(true);
    });

    it("should detect password pattern", () => {
      expect(containsSecrets("password=mysecretpassword123")).toBe(true);
    });

    it("should allow safe string", () => {
      expect(containsSecrets("Hello World")).toBe(false);
    });
  });

  describe("redactSecrets", () => {
    it("should redact password in string", () => {
      const result = redactSecrets("password=mysecretpassword123");
      expect(result).not.toContain("mysecretpassword123");
    });

    it("should redact API key", () => {
      const result = redactSecrets("api_key=sk_live_1234567890abcdef");
      expect(result).not.toContain("sk_live_1234567890abcdef");
    });

    it("should redact multiple secrets", () => {
      const result = redactSecrets(
        "password=secret123 and api_key=key456"
      );
      expect(result).not.toContain("secret123");
      expect(result).not.toContain("key456");
    });
  });

  describe("validateSecret", () => {
    it("should validate strong password", () => {
      expect(
        validateSecret("MySecurePassword123!", { minLength: 8 })
      ).toBe(true);
    });

    it("should reject weak password", () => {
      expect(validateSecret("password")).toBe(false);
    });

    it("should reject short password", () => {
      expect(validateSecret("abc123!", { minLength: 16 })).toBe(false);
    });

    it("should require uppercase", () => {
      expect(validateSecret("password123!", { requireUppercase: true })).toBe(
        false
      );
    });

    it("should require lowercase", () => {
      expect(validateSecret("PASSWORD123!", { requireLowercase: true })).toBe(
        false
      );
    });

    it("should require numbers", () => {
      expect(validateSecret("Password!", { requireNumbers: true })).toBe(false);
    });

    it("should require special characters", () => {
      expect(validateSecret("Password123", { requireSpecialChars: true })).toBe(
        false
      );
    });
  });

  describe("generateSecureSecret", () => {
    it("should generate random secret", () => {
      const secret = generateSecureSecret(32);
      expect(secret).toHaveLength(32);
    });

    it("should generate different secrets", () => {
      const secret1 = generateSecureSecret(32);
      const secret2 = generateSecureSecret(32);
      expect(secret1).not.toBe(secret2);
    });

    it("should generate secret with default length", () => {
      const secret = generateSecureSecret();
      expect(secret).toHaveLength(32);
    });
  });
});
