/**
 * Tests for HTTP security headers utilities.
 */

import { describe, it, expect } from "vitest";
import {
  addSecurityHeaders,
  generateCorsHeaders,
} from "./http-security-headers.js";

describe("HTTP Security Headers", () => {
  describe("addSecurityHeaders", () => {
    it("should add security headers to response", () => {
      const headers: Record<string, string> = {};
      
      const mockRes = {
        setHeader(key: string, value: string) {
          headers[key] = value;
        },
      } as any;

      addSecurityHeaders(mockRes);

      expect(headers["Content-Security-Policy"]).toBeDefined();
      expect(headers["X-Content-Type-Options"]).toBe("nosniff");
      expect(headers["X-Frame-Options"]).toBe("DENY");
      expect(headers["X-XSS-Protection"]).toBe("1; mode=block");
      expect(headers["Strict-Transport-Security"]).toBeDefined();
      expect(headers["Referrer-Policy"]).toBeDefined();
      expect(headers["Permissions-Policy"]).toBeDefined();
      expect(headers["Cache-Control"]).toBe("no-store, no-cache, must-revalidate, proxy-revalidate");
    });

    it("should allow custom CSP directives", () => {
      const headers: Record<string, string> = {};
      
      const mockRes = {
        setHeader(key: string, value: string) {
          headers[key] = value;
        },
      } as any;

      addSecurityHeaders(mockRes, {
        contentSecurityPolicyDirectives: ["img-src 'self' example.com"],
      });

      expect(headers["Content-Security-Policy"]).toContain("img-src 'self' example.com");
    });

    it("should allow disabling headers", () => {
      const headers: Record<string, string> = {};
      
      const mockRes = {
        setHeader(key: string, value: string) {
          headers[key] = value;
        },
      } as any;

      addSecurityHeaders(mockRes, {
        contentSecurityPolicy: false,
        strictTransportSecurity: false,
      });

      expect(headers["Content-Security-Policy"]).toBeUndefined();
      expect(headers["Strict-Transport-Security"]).toBeUndefined();
    });
  });

  describe("generateCorsHeaders", () => {
    it("should generate CORS headers with allowed origin", () => {
      const req = {
        headers: {
          origin: "https://example.com",
        },
      } as any;

      const headers = generateCorsHeaders(req, {
        allowedOrigins: ["https://example.com"],
      });

      expect(headers["Access-Control-Allow-Origin"]).toBe("https://example.com");
    });

    it("should allow all origins with wildcard", () => {
      const req = {} as any;

      const headers = generateCorsHeaders(req, {
        allowedOrigins: ["*"],
      });

      expect(headers["Access-Control-Allow-Origin"]).toBe("*");
    });

    it("should set allowed methods", () => {
      const req = {} as any;

      const headers = generateCorsHeaders(req, {
        allowedMethods: ["GET", "POST"],
      });

      expect(headers["Access-Control-Allow-Methods"]).toBe("GET, POST");
    });

    it("should set max age", () => {
      const req = {} as any;

      const headers = generateCorsHeaders(req, {
        maxAge: 3600,
      });

      expect(headers["Access-Control-Max-Age"]).toBe("3600");
    });
  });

  describe("Security Headers", () => {
    it("should include Content-Security-Policy", () => {
      const headers: Record<string, string> = {};
      
      const mockRes = {
        setHeader(key: string, value: string) {
          headers[key] = value;
        },
      } as any;

      addSecurityHeaders(mockRes);

      expect(headers["Content-Security-Policy"]).toContain("default-src 'self'");
    });

    it("should include X-Content-Type-Options", () => {
      const headers: Record<string, string> = {};
      
      const mockRes = {
        setHeader(key: string, value: string) {
          headers[key] = value;
        },
      } as any;

      addSecurityHeaders(mockRes);

      expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    });

    it("should include X-Frame-Options", () => {
      const headers: Record<string, string> = {};
      
      const mockRes = {
        setHeader(key: string, value: string) {
          headers[key] = value;
        },
      } as any;

      addSecurityHeaders(mockRes);

      expect(headers["X-Frame-Options"]).toBe("DENY");
    });

    it("should include X-XSS-Protection", () => {
      const headers: Record<string, string> = {};
      
      const mockRes = {
        setHeader(key: string, value: string) {
          headers[key] = value;
        },
      } as any;

      addSecurityHeaders(mockRes);

      expect(headers["X-XSS-Protection"]).toBe("1; mode=block");
    });

    it("should include Strict-Transport-Security", () => {
      const headers: Record<string, string> = {};
      
      const mockRes = {
        setHeader(key: string, value: string) {
          headers[key] = value;
        },
      } as any;

      addSecurityHeaders(mockRes);

      expect(headers["Strict-Transport-Security"]).toContain("max-age=31536000");
    });

    it("should include Referrer-Policy", () => {
      const headers: Record<string, string> = {};
      
      const mockRes = {
        setHeader(key: string, value: string) {
          headers[key] = value;
        },
      } as any;

      addSecurityHeaders(mockRes);

      expect(headers["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
    });

    it("should include Permissions-Policy", () => {
      const headers: Record<string, string> = {};
      
      const mockRes = {
        setHeader(key: string, value: string) {
          headers[key] = value;
        },
      } as any;

      addSecurityHeaders(mockRes);

      expect(headers["Permissions-Policy"]).toContain("geolocation=()");
    });

    it("should include Cache-Control", () => {
      const headers: Record<string, string> = {};
      
      const mockRes = {
        setHeader(key: string, value: string) {
          headers[key] = value;
        },
      } as any;

      addSecurityHeaders(mockRes);

      expect(headers["Cache-Control"]).toContain("no-store");
    });
  });
});
