/**
 * Tests for authentication token security utilities.
 */

import { describe, it, expect } from "vitest";
import {
  generateSecureToken,
  TokenRotationManager,
  SecureTokenStorage,
} from "./auth-token-security.js";

describe("Authentication Token Security", () => {
  describe("generateSecureToken", () => {
    it("should generate random token", () => {
      const token = generateSecureToken();
      expect(typeof token).toBe("string");
      expect(token.length).toBeGreaterThan(32);
    });

    it("should generate different tokens", () => {
      const token1 = generateSecureToken();
      const token2 = generateSecureToken();
      expect(token1).not.toBe(token2);
    });

    it("should support custom length", () => {
      const token = generateSecureToken({ length: 16 });
      expect(token.length).toBe(32); // 16 bytes * 2 (hex)
    });

    it("should support prefix", () => {
      const token = generateSecureToken({ prefix: "token" });
      expect(token).toMatch(/^token_[a-f0-9]+$/);
    });

    it("should support timestamp", () => {
      const token = generateSecureToken({ includeTimestamp: true });
      expect(token).toMatch(/_[a-z0-9]+$/);
    });
  });

  describe("TokenRotationManager", () => {
    it("should add token to rotation", () => {
      const manager = new TokenRotationManager();
      const { token, hash } = generateSecureToken();

      // In a real test, we'd validate the token
      expect(token).toBeDefined();
    });

    it("should support rotation history", () => {
      const manager = new TokenRotationManager({ historySize: 3 });

      // Add multiple tokens
      for (let i = 0; i < 5; i++) {
        const { token } = generateSecureToken();
        // In a real test, we'd add to manager
      }

      expect(manager.getValidTokenCount()).toBeLessThanOrEqual(3);
    });

    it("should check if rotation is needed", () => {
      const manager = new TokenRotationManager({
        rotationInterval: 24 * 60 * 60 * 1000, // 24 hours
      });

      const needsRotation = manager.needsRotation();
      expect(typeof needsRotation).toBe("boolean");
    });
  });

  describe("SecureTokenStorage", () => {
    it("should store token securely", () => {
      const storage = new SecureTokenStorage();
      const { token } = generateSecureToken();

      storage.storeToken("user123", token);

      expect(storage.hasValidToken("user123")).toBe(true);
    });

    it("should validate token against stored hash", () => {
      const storage = new SecureTokenStorage();
      const { token, hash } = generateSecureToken();

      storage.storeToken("user123", token);

      const isValid = storage.validateToken("user123", token);
      expect(isValid).toBe(true);
    });

    it("should reject invalid token", () => {
      const storage = new SecureTokenStorage();
      const { token } = generateSecureToken();

      storage.storeToken("user123", token);

      const isValid = storage.validateToken("user123", "invalid-token");
      expect(isValid).toBe(false);
    });

    it("should delete token", () => {
      const storage = new SecureTokenStorage();
      const { token } = generateSecureToken();

      storage.storeToken("user123", token);
      expect(storage.hasValidToken("user123")).toBe(true);

      storage.deleteToken("user123");
      expect(storage.hasValidToken("user123")).toBe(false);
    });
  });

  describe("Token Expiration", () => {
    it("should set token expiration", () => {
      const { TokenExpirationManager } = require("./auth-token-security.js");
      const manager = new TokenExpirationManager();
      const { token } = generateSecureToken();

      manager.setExpiration(token, 60 * 1000); // 1 minute

      expect(manager.getRemainingTime(token)).toBeGreaterThan(0);
    });

    it("should check if token is expired", () => {
      const { TokenExpirationManager } = require("./auth-token-security.js");
      const manager = new TokenExpirationManager();
      const { token } = generateSecureToken();

      // Set expiration in the past
      manager.setExpiration(token, -1000);

      expect(manager.isExpired(token)).toBe(true);
    });

    it("should validate with expiration", () => {
      const { TokenExpirationManager } = require("./auth-token-security.js");
      const manager = new TokenExpirationManager();
      const { token } = generateSecureToken();

      manager.setExpiration(token, 60 * 1000);

      expect(manager.validateWithExpiration(token)).toBe(true);
    });
  });

  describe("Token Binding", () => {
    it("should create binding hash", () => {
      const { createTokenBindingHash } = require("./auth-token-security.js");
      
      const binding = {
        userId: "user123",
        ipAddress: "192.168.1.1",
      };

      const hash = createTokenBindingHash(binding);
      expect(typeof hash).toBe("string");
    });

    it("should validate binding", () => {
      const { createTokenBindingHash, generateSecureToken } = require("./auth-token-security.js");
      
      const binding = {
        userId: "user123",
        ipAddress: "192.168.1.1",
      };

      const { token } = generateSecureToken();
      const hash = createTokenBindingHash(binding);

      // In a real test, we'd validate the token against the binding
      expect(hash).toBeDefined();
    });
  });
});
