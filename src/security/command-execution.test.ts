/**
 * Tests for command execution utilities.
 */

import { describe, it, expect } from "vitest";
import {
  validateCommand,
  containsCommandInjection,
  sanitizeCommand,
  parseCommandArgs,
} from "./command-execution.js";

describe("Command Execution", () => {
  describe("validateCommand", () => {
    it("should validate safe command", () => {
      expect(validateCommand("ls -la")).toBe(true);
    });

    it("should reject command with semicolon", () => {
      expect(validateCommand("ls; rm -rf /")).toBe(false);
    });

    it("should reject command with pipe", () => {
      expect(validateCommand("ls | cat")).toBe(false);
    });

    it("should reject command with ampersand", () => {
      expect(validateCommand("ls & cat")).toBe(false);
    });

    it("should reject command with command substitution", () => {
      expect(validateCommand("ls `whoami`")).toBe(false);
    });

    it("should reject command with injection", () => {
      expect(validateCommand("ls && cat")).toBe(false);
    });

    it("should reject empty command", () => {
      expect(validateCommand("")).toBe(false);
    });

    it("should reject long command", () => {
      expect(validateCommand("a".repeat(2048))).toBe(false);
    });
  });

  describe("containsCommandInjection", () => {
    it("should detect semicolon injection", () => {
      expect(containsCommandInjection("ls; rm -rf /")).toBe(true);
    });

    it("should detect pipe injection", () => {
      expect(containsCommandInjection("ls | cat")).toBe(true);
    });

    it("should detect ampersand injection", () => {
      expect(containsCommandInjection("ls & cat")).toBe(true);
    });

    it("should detect command substitution", () => {
      expect(containsCommandInjection("ls `whoami`")).toBe(true);
    });

    it("should detect command chaining", () => {
      expect(containsCommandInjection("ls && cat")).toBe(true);
    });

    it("should allow safe command", () => {
      expect(containsCommandInjection("ls -la")).toBe(false);
    });
  });

  describe("sanitizeCommand", () => {
    it("should remove dangerous characters", () => {
      expect(sanitizeCommand("ls; rm -rf /")).toBe("lsrm-rf");
    });

    it("should keep safe characters", () => {
      expect(sanitizeCommand("ls -la /tmp")).toBe("ls-la/tmp");
    });
  });

  describe("parseCommandArgs", () => {
    it("should parse simple command", () => {
      expect(parseCommandArgs("ls -la")).toEqual(["ls", "-la"]);
    });

    it("should parse command with multiple args", () => {
      expect(parseCommandArgs("ls -la /tmp")).toEqual(["ls", "-la", "/tmp"]);
    });

    it("should remove dangerous characters from args", () => {
      expect(parseCommandArgs("ls; rm -rf /")).toEqual(["lsrm-rf"]);
    });
  });

  describe("containsDangerousShellChars", () => {
    it("should detect semicolon", () => {
      expect(containsDangerousShellChars("ls; rm -rf /")).toBe(true);
    });

    it("should detect pipe", () => {
      expect(containsDangerousShellChars("ls | cat")).toBe(true);
    });

    it("should detect ampersand", () => {
      expect(containsDangerousShellChars("ls & cat")).toBe(true);
    });

    it("should allow safe command", () => {
      expect(containsDangerousShellChars("ls -la")).toBe(false);
    });
  });
});
