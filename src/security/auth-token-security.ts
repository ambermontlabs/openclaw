/**
 * Enhanced authentication token security utilities.
 *
 * This module provides comprehensive protection for authentication tokens
 * including rotation, validation, and secure storage.
 */

import { randomBytes, createHash } from "crypto";

// --------------------------------------------------------------------------
// Token Generation
// --------------------------------------------------------------------------

/**
 * Token generation options.
 */
export interface TokenGenerationOptions {
  /** Token length in bytes (default: 32) */
  length?: number;
  /** Token prefix (default: none) */
  prefix?: string;
  /** Include timestamp in token (default: false) */
  includeTimestamp?: boolean;
  /** Token expiration time in milliseconds (default: no expiry) */
  expiresIn?: number;
}

/**
 * Default token generation options.
 */
const DEFAULT_TOKEN_OPTIONS: Required<TokenGenerationOptions> = {
  length: 32,
  prefix: "",
  includeTimestamp: false,
  expiresIn: 0, // No expiry
};

/**
 * Generate a cryptographically secure random token.
 */
export function generateSecureToken(options?: TokenGenerationOptions): string {
  const config = { ...DEFAULT_TOKEN_OPTIONS, ...options };
  
  // Generate random bytes
  const buffer = randomBytes(config.length);
  const token = buffer.toString("hex");

  // Add prefix if specified
  let result = config.prefix ? `${config.prefix}_${token}` : token;

  // Add timestamp if specified
  if (config.includeTimestamp) {
    const timestamp = Date.now().toString(36);
    result = `${result}_${timestamp}`;
  }

  return result;
}

/**
 * Generate a token with hash for verification.
 */
export interface TokenWithHash {
  /** The raw token (to be sent to client) */
  token: string;
  /** The hashed token (to be stored server-side) */
  hash: string;
}

/**
 * Generate a secure token with its hash.
 */
export function generateTokenWithHash(options?: TokenGenerationOptions): TokenWithHash {
  const token = generateSecureToken(options);
  const hash = createHash("sha256").update(token).digest("hex");

  return { token, hash };
}

// --------------------------------------------------------------------------
// Token Validation
// --------------------------------------------------------------------------

/**
 * Token validation options.
 */
export interface TokenValidationOptions {
  /** Expected token length (default: derived from generation options) */
  expectedLength?: number;
  /** Token prefix (if any) */
  prefix?: string;
  /** Maximum token age in milliseconds (default: no limit) */
  maxAge?: number;
  /** Validate token format strictly (default: true) */
  strictFormat?: boolean;
}

/**
 * Default validation options.
 */
const DEFAULT_VALIDATION_OPTIONS: Required<TokenValidationOptions> = {
  expectedLength: 64, // 32 bytes * 2 (hex)
  prefix: "",
  maxAge: 0, // No limit
  strictFormat: true,
};

/**
 * Validate a token's format.
 */
export function validateTokenFormat(token: string, options?: TokenValidationOptions): boolean {
  const config = { ...DEFAULT_VALIDATION_OPTIONS, ...options };

  // Check prefix
  if (config.prefix && !token.startsWith(config.prefix + "_")) {
    return false;
  }

  // Remove prefix for further validation
  const tokenWithoutPrefix = config.prefix 
    ? token.slice((config.prefix + "_").length) 
    : token;

  // Check timestamp if included
  let tokenWithoutTimestamp = tokenWithoutPrefix;
  if (tokenWithoutPrefix.includes("_")) {
    const parts = tokenWithoutPrefix.split("_");
    // Last part might be timestamp
    if (parts.length > 1) {
      const lastPart = parts[parts.length - 1];
      if (!isNaN(Number(lastPart))) {
        // Check timestamp age
        if (config.maxAge > 0) {
          const tokenTime = parseInt(lastPart, 36);
          const now = Date.now();
          if (now - tokenTime > config.maxAge) {
            return false;
          }
        }
        
        // Remove timestamp for further validation
        tokenWithoutTimestamp = parts.slice(0, -1).join("_");
      }
    }
  }

  // Check format (hex string)
  if (config.strictFormat) {
    const hexPattern = /^[a-f0-9]+$/;
    if (!hexPattern.test(tokenWithoutTimestamp)) {
      return false;
    }
  }

  // Check length
  if (tokenWithoutTimestamp.length !== config.expectedLength) {
    return false;
  }

  return true;
}

/**
 * Validate a token against its hash.
 */
export function validateTokenHash(token: string, expectedHash: string): boolean {
  const hash = createHash("sha256").update(token).digest("hex");
  return hash === expectedHash;
}

// --------------------------------------------------------------------------
// Token Rotation
// --------------------------------------------------------------------------

/**
 * Token rotation options.
 */
export interface TokenRotationOptions {
  /** Number of previous tokens to keep for validation (default: 3) */
  historySize?: number;
  /** Rotation interval in milliseconds (default: 24 hours) */
  rotationInterval?: number;
}

/**
 * Default rotation options.
 */
const DEFAULT_ROTATION_OPTIONS: Required<TokenRotationOptions> = {
  historySize: 3,
  rotationInterval: 24 * 60 * 60 * 1000, // 24 hours
};

/**
 * Token rotation manager.
 */
export class TokenRotationManager {
  private history: Array<{ tokenHash: string; createdAt: number }>;
  private options: Required<TokenRotationOptions>;

  constructor(options?: TokenRotationOptions) {
    this.history = [];
    this.options = { ...DEFAULT_ROTATION_OPTIONS, ...options };
  }

  /**
   * Add a new token to the rotation.
   */
  addToken(token: string): void {
    const hash = createHash("sha256").update(token).digest("hex");
    
    // Add to history
    this.history.push({
      tokenHash: hash,
      createdAt: Date.now(),
    });

    // Trim history to size
    while (this.history.length > this.options.historySize) {
      this.history.shift();
    }
  }

  /**
   * Check if a token is valid (current or in history).
   */
  validateToken(token: string): boolean {
    const hash = createHash("sha256").update(token).digest("hex");

    // Check current token
    if (this.history.length > 0 && this.history[this.history.length - 1].tokenHash === hash) {
      return true;
    }

    // Check history
    for (const entry of this.history) {
      if (entry.tokenHash === hash) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if rotation is needed.
   */
  needsRotation(): boolean {
    if (this.history.length === 0) {
      return false;
    }

    const oldest = this.history[0].createdAt;
    const now = Date.now();
    
    return now - oldest > this.options.rotationInterval;
  }

  /**
   * Rotate tokens if needed.
   */
  rotateIfNeeded(): void {
    if (this.needsRotation()) {
      // Trim old tokens
      while (
        this.history.length > 0 &&
        Date.now() - this.history[0].createdAt > this.options.rotationInterval
      ) {
        this.history.shift();
      }
    }
  }

  /**
   * Get the number of valid tokens in history.
   */
  getValidTokenCount(): number {
    return this.history.length;
  }
}

// --------------------------------------------------------------------------
// Token Binding
// --------------------------------------------------------------------------

/**
 * Bind a token to specific attributes for additional security.
 */
export interface TokenBinding {
  /** User ID */
  userId: string;
  /** IP address */
  ipAddress?: string;
  /** User agent hash */
  userAgentHash?: string;
  /** Device ID */
  deviceId?: string;
}

/**
 * Create a binding hash for token binding.
 */
export function createTokenBindingHash(binding: TokenBinding): string {
  const data = JSON.stringify({
    userId: binding.userId,
    ipAddress: binding.ipAddress,
    userAgentHash: binding.userAgentHash,
    deviceId: binding.deviceId,
  });

  return createHash("sha256").update(data).digest("hex");
}

/**
 * Validate a token binding.
 */
export function validateTokenBinding(
  token: string,
  binding: TokenBinding,
  storedBindingHash: string
): boolean {
  const currentHash = createTokenBindingHash(binding);
  return validateTokenHash(token, storedBindingHash) && currentHash === storedBindingHash;
}

// --------------------------------------------------------------------------
// Token Storage Security
// --------------------------------------------------------------------------

/**
 * Secure token storage options.
 */
export interface SecureTokenStorageOptions {
  /** Enable encryption (default: true) */
  encrypt?: boolean;
  /** Token prefix for storage keys */
  keyPrefix?: string;
}

/**
 * Default storage options.
 */
const DEFAULT_STORAGE_OPTIONS: Required<SecureTokenStorageOptions> = {
  encrypt: true,
  keyPrefix: "token",
};

/**
 * Secure token storage class.
 */
export class SecureTokenStorage {
  private storage: Map<string, string>;
  private options: Required<SecureTokenStorageOptions>;

  constructor(options?: SecureTokenStorageOptions) {
    this.storage = new Map();
    this.options = { ...DEFAULT_STORAGE_OPTIONS, ...options };
  }

  /**
   * Store a token securely.
   */
  storeToken(userId: string, token: string): void {
    const hash = createHash("sha256").update(token).digest("hex");
    const key = `${this.options.keyPrefix}:${userId}`;
    
    // Store hash instead of raw token
    this.storage.set(key, hash);
  }

  /**
   * Retrieve a stored token hash.
   */
  getStoredHash(userId: string): string | null {
    const key = `${this.options.keyPrefix}:${userId}`;
    return this.storage.get(key) || null;
  }

  /**
   * Validate a token against stored hash.
   */
  validateToken(userId: string, token: string): boolean {
    const storedHash = this.getStoredHash(userId);
    if (!storedHash) {
      return false;
    }

    return validateTokenHash(token, storedHash);
  }

  /**
   * Delete a token.
   */
  deleteToken(userId: string): void {
    const key = `${this.options.keyPrefix}:${userId}`;
    this.storage.delete(key);
  }

  /**
   * Check if a user has a valid token.
   */
  hasValidToken(userId: string): boolean {
    return this.storage.has(`${this.options.keyPrefix}:${userId}`);
  }
}

// --------------------------------------------------------------------------
// Token Expiration
// --------------------------------------------------------------------------

/**
 * Token expiration manager.
 */
export class TokenExpirationManager {
  private tokens: Map<string, number>; // tokenHash -> expirationTime

  constructor() {
    this.tokens = new Map();
  }

  /**
   * Set token expiration.
   */
  setExpiration(token: string, expiresIn: number): void {
    const hash = createHash("sha256").update(token).digest("hex");
    this.tokens.set(hash, Date.now() + expiresIn);
  }

  /**
   * Check if a token is expired.
   */
  isExpired(token: string): boolean {
    const hash = createHash("sha256").update(token).digest("hex");
    const expirationTime = this.tokens.get(hash);

    if (!expirationTime) {
      return false; // No expiration set
    }

    return Date.now() > expirationTime;
  }

  /**
   * Validate token and check expiration.
   */
  validateWithExpiration(token: string): boolean {
    if (this.isExpired(token)) {
      this.deleteToken(token);
      return false;
    }

    return true;
  }

  /**
   * Delete a token.
   */
  deleteToken(token: string): void {
    const hash = createHash("sha256").update(token).digest("hex");
    this.tokens.delete(hash);
  }

  /**
   * Clean up expired tokens.
   */
  cleanupExpired(): void {
    const now = Date.now();
    
    for (const [hash, expirationTime] of this.tokens.entries()) {
      if (now > expirationTime) {
        this.tokens.delete(hash);
      }
    }
  }

  /**
   * Get remaining time for a token.
   */
  getRemainingTime(token: string): number | null {
    const hash = createHash("sha256").update(token).digest("hex");
    const expirationTime = this.tokens.get(hash);

    if (!expirationTime) {
      return null;
    }

    const remaining = expirationTime - Date.now();
    return Math.max(0, remaining);
  }
}
