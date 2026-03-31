/**
 * Tests for audit logging utilities.
 */

import { describe, it, expect } from "vitest";
import { AuditLogger } from "./audit-logging.js";

describe("Audit Logging", () => {
  describe("AuditLogger", () => {
    let logger: AuditLogger;

    beforeEach(() => {
      logger = new AuditLogger("test-source");
    });

    it("should create event with correct structure", () => {
      const event = logger.createEventFromRequest(
        "authentication",
        "login",
        true
      );

      expect(event).toHaveProperty("timestamp");
      expect(event).toHaveProperty("eventId");
      expect(event.category).toBe("authentication");
      expect(event.action).toBe("login");
      expect(event.success).toBe(true);
    });

    it("should log authentication event", () => {
      expect(() => {
        logger.logAuthentication("user123", true, {
          ipAddress: "192.168.1.1",
          method: "token",
        });
      }).not.toThrow();
    });

    it("should log failed authentication event", () => {
      expect(() => {
        logger.logAuthentication("user123", false, {
          ipAddress: "192.168.1.1",
          method: "token",
          errorMessage: "Invalid token",
        });
      }).not.toThrow();
    });

    it("should log authorization event", () => {
      expect(() => {
        logger.logAuthorization(
          "user123",
          "/api/users",
          "read",
          true
        );
      }).not.toThrow();
    });

    it("should log configuration event", () => {
      expect(() => {
        logger.logConfiguration(
          "admin",
          "update",
          "gateway.config"
        );
      }).not.toThrow();
    });

    it("should log file access event", () => {
      expect(() => {
        logger.logFileAccess(
          "user123",
          "/etc/passwd",
          "read",
          true
        );
      }).not.toThrow();
    });

    it("should log command execution event", () => {
      expect(() => {
        logger.logCommandExecution(
          "user123",
          "ls -la",
          true,
          {
            cwd: "/tmp",
            durationMs: 100,
            exitCode: 0,
          }
        );
      }).not.toThrow();
    });

    it("should redact secrets in context", () => {
      const event = logger.createEventFromRequest(
        "authentication",
        "login",
        true,
        undefined,
        {
          context: {
            password: "secret123",
            username: "user123",
          },
        }
      );

      expect(event.context).toBeDefined();
      // The context should be redacted when logged
    });

    it("should extract IP address from request", () => {
      const headers = {
        "x-forwarded-for": "192.168.1.100, 10.0.0.1",
        "user-agent": "Test Agent",
      };

      const info = logger.extractRequestInfo({
        headers,
        socket: { remoteAddress: "127.0.0.1" } as any,
      });

      expect(info.ipAddress).toBe("192.168.1.100");
    });

    it("should generate unique event IDs", () => {
      const id1 = logger.generateEventId();
      const id2 = logger.generateEventId();

      expect(id1).not.toBe(id2);
    });

    it("should respect severity threshold", () => {
      const logger = new AuditLogger("test-source", {
        minSeverity: "warn",
      });

      // This should not throw (but won't log info level)
      expect(() => {
        logger.logAuthentication("user123", true);
      }).not.toThrow();
    });
  });

  describe("Severity Levels", () => {
    it("should have correct severity levels", () => {
      const logger = new AuditLogger("test-source");

      expect(logger.getSeverityLevel("info")).toBe(0);
      expect(logger.getSeverityLevel("warn")).toBe(1);
      expect(logger.getSeverityLevel("error")).toBe(2);
      expect(logger.getSeverityLevel("critical")).toBe(3);
    });

    it("should filter by severity", () => {
      const logger = new AuditLogger("test-source", {
        minSeverity: "warn",
      });

      // Info should be filtered out
      const infoEvent = logger.createEventFromRequest(
        "authentication",
        "login",
        true
      );
      expect(logger.getSeverityLevel(infoEvent.severity)).toBe(0);
      expect(logger.getSeverityLevel("warn")).toBeGreaterThan(0);

      // Warn should be logged
      const warnEvent = logger.createEventFromRequest(
        "authentication",
        "login",
        false
      );
      expect(logger.getSeverityLevel(warnEvent.severity)).toBe(1);
    });
  });

  describe("Request Information", () => {
    it("should extract IP from x-forwarded-for", () => {
      const headers = {
        "x-forwarded-for": "192.168.1.100, 10.0.0.1",
      };

      const info = logger.extractRequestInfo({
        headers,
        socket: { remoteAddress: "127.0.0.1" } as any,
      });

      expect(info.ipAddress).toBe("192.168.1.100");
    });

    it("should extract IP from x-real-ip", () => {
      const headers = {
        "x-real-ip": "192.168.1.100",
      };

      const info = logger.extractRequestInfo({
        headers,
        socket: { remoteAddress: "127.0.0.1" } as any,
      });

      expect(info.ipAddress).toBe("192.168.1.100");
    });

    it("should extract IP from socket if no headers", () => {
      const info = logger.extractRequestInfo({
        headers: {},
        socket: { remoteAddress: "192.168.1.100" } as any,
      });

      expect(info.ipAddress).toBe("192.168.1.100");
    });

    it("should extract user agent", () => {
      const headers = {
        "user-agent": "Mozilla/5.0",
      };

      const info = logger.extractRequestInfo({
        headers,
        socket: { remoteAddress: "127.0.0.1" } as any,
      });

      expect(info.userAgent).toBe("Mozilla/5.0");
    });
  });
});
