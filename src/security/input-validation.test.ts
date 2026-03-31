/**
 * Tests for input validation utilities.
 */

import { describe, it, expect } from "vitest";
import {
  containsDangerousShellChars,
  isValidShellArgument,
  sanitizeShellArgument,
  escapeHtml,
  escapeJavaScript,
  containsPathTraversal,
  isValidPath,
  isValidUrl,
} from "./input-validation.js";

describe("Input Validation", () => {
  describe("containsDangerousShellChars", () => {
    it("should detect command separator", () => {
      expect(containsDangerousShellChars("ls; rm -rf /")).toBe(true);
    });

    it("should detect pipe", () => {
      expect(containsDangerousShellChars("ls | cat")).toBe(true);
    });

    it("should detect ampersand", () => {
      expect(containsDangerousShellChars("ls & cat")).toBe(true);
    });

    it("should detect command substitution", () => {
      expect(containsDangerousShellChars("ls `whoami`")).toBe(true);
    });

    it("should detect command chaining", () => {
      expect(containsDangerousShellChars("ls && cat")).toBe(true);
    });

    it("should allow safe command", () => {
      expect(containsDangerousShellChars("ls -la")).toBe(false);
    });
  });

  describe("isValidShellArgument", () => {
    it("should validate safe argument", () => {
      expect(isValidShellArgument("ls -la /tmp")).toBe(true);
    });

    it("should reject argument with semicolon", () => {
      expect(isValidShellArgument("ls; rm -rf /")).toBe(false);
    });

    it("should reject empty string", () => {
      expect(isValidShellArgument("")).toBe(false);
    });

    it("should reject long string", () => {
      expect(isValidShellArgument("a".repeat(2048))).toBe(false);
    });
  });

  describe("sanitizeShellArgument", () => {
    it("should remove dangerous characters", () => {
      expect(sanitizeShellArgument("ls; rm -rf /")).toBe("lsrm-rf");
    });

    it("should keep safe characters", () => {
      expect(sanitizeShellArgument("ls -la /tmp")).toBe("ls-la/tmp");
    });
  });

  describe("escapeHtml", () => {
    it("should escape ampersand", () => {
      expect(escapeHtml("A & B")).toBe("A &amp; B");
    });

    it("should escape less than", () => {
      expect(escapeHtml("<script>")).toBe("&lt;script&gt;");
    });

    it("should escape greater than", () => {
      expect(escapeHtml(">")).toBe("&gt;");
    });

    it("should escape quotes", () => {
      expect(escapeHtml('test"')).toBe("test&quot;");
    });
  });

  describe("escapeJavaScript", () => {
    it("should escape backslash", () => {
      expect(escapeJavaScript("\\")).toBe("\\\\");
    });

    it("should escape single quote", () => {
      expect(escapeJavaScript("'")).toBe("\\'");
    });

    it("should escape double quote", () => {
      expect(escapeJavaScript('"')).toBe('\\"');
    });

    it("should escape newline", () => {
      expect(escapeJavaScript("\n")).toBe("\\n");
    });
  });

  describe("containsPathTraversal", () => {
    it("should detect directory traversal", () => {
      expect(containsPathTraversal("../../etc/passwd")).toBe(true);
    });

    it("should detect /. pattern", () => {
      expect(containsPathTraversal("/etc/./passwd")).toBe(true);
    });

    it("should allow safe path", () => {
      expect(containsPathTraversal("file.txt")).toBe(false);
    });
  });

  describe("isValidPath", () => {
    it("should validate safe path", () => {
      expect(isValidPath("file.txt")).toBe(true);
    });

    it("should reject path traversal", () => {
      expect(isValidPath("../../etc/passwd")).toBe(false);
    });

    it("should reject absolute path by default", () => {
      expect(isValidPath("/etc/passwd")).toBe(false);
    });

    it("should allow absolute path when specified", () => {
      expect(isValidPath("/etc/passwd", true)).toBe(true);
    });

    it("should reject null byte", () => {
      expect(isValidPath("file\0.txt")).toBe(false);
    });
  });

  describe("isValidUrl", () => {
    it("should validate http URL", () => {
      expect(isValidUrl("https://example.com")).toBe(true);
    });

    it("should reject javascript protocol", () => {
      expect(isValidUrl("javascript:alert(1)")).toBe(false);
    });

    it("should reject file protocol", () => {
      expect(isValidUrl("file:///etc/passwd")).toBe(false);
    });

    it("should reject invalid URL", () => {
      expect(isValidUrl("not-a-url")).toBe(false);
    });
  });
});
