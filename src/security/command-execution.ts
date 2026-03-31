/**
 * Secure command execution utilities.
 *
 * This module provides safe wrappers for executing shell commands
 * with built-in protection against command injection and other attacks.
 */

import { spawn, SpawnOptions } from "child_process";
import { promisify } from "util";

const execAsync = promisify(require("child_process").exec);

// --------------------------------------------------------------------------
// Command Validation
// --------------------------------------------------------------------------

/**
 * Validate a command string for safe execution.
 */
export function validateCommand(command: string): boolean {
  if (typeof command !== "string" || command.length === 0) {
    return false;
  }

  // Check for dangerous shell metacharacters
  if (containsDangerousShellChars(command)) {
    return false;
  }

  // Check for dangerous commands
  const dangerousCommands = [
    "rm -rf",
    "mkfs",
    "dd",
    "chmod -R 777",
    "chown -R",
    ":(){ :|:& };:",
    "eval",
    "exec",
  ];

  for (const dangerous of dangerousCommands) {
    if (command.includes(dangerous)) {
      return false;
    }
  }

  // Check for command injection attempts
  if (containsCommandInjection(command)) {
    return false;
  }

  // Check length limit
  if (command.length > 1024) {
    return false;
  }

  return true;
}

/**
 * Check if a command contains injection attempts.
 */
export function containsCommandInjection(command: string): boolean {
  // Check for command separators
  const injectionPatterns = [
    /;/,                    // Command separator
    /\|/,                   // Pipe
    /&/,                    // Background/ampersand
    /`/,                    // Command substitution
    /\$\(/,                 // Command substitution $(...)
    /\$\{/,                 // Variable expansion
    /<[^>]/,                // Input redirection
    />[^>]/,                // Output redirection
  ];

  for (const pattern of injectionPatterns) {
    if (pattern.test(command)) {
      return true;
    }
  }

  // Check for dangerous command chaining
  if (command.includes("&&") || command.includes("||")) {
    return true;
  }

  // Check for newlines (command injection via multiline)
  if (command.includes("\n") || command.includes("\r")) {
    return true;
  }

  return false;
}

/**
 * Sanitize a command string for safe execution.
 */
export function sanitizeCommand(command: string): string {
  // Remove dangerous characters but keep safe ones
  return command.replace(/[^a-zA-Z0-9_\-./\s]/g, "");
}

// --------------------------------------------------------------------------
// Safe Command Execution
// --------------------------------------------------------------------------

/**
 * Options for safe command execution.
 */
export interface SafeExecOptions {
  /** Working directory for the command */
  cwd?: string;
  /** Environment variables */
  env?: Record<string, string>;
  /** Maximum execution time in milliseconds */
  timeout?: number;
  /** Maximum output size in bytes */
  maxBuffer?: number;
  /** Additional validation callback */
  validateArgs?: (args: string[]) => boolean;
}

/**
 * Execute a command safely with validation.
 */
export async function safeExec(
  command: string,
  options?: SafeExecOptions
): Promise<{ stdout: string; stderr: string }> {
  // Validate the command
  if (!validateCommand(command)) {
    throw new Error("Invalid or dangerous command");
  }

  // Parse the command safely
  const args = parseCommandArgs(command);
  
  if (args.length === 0) {
    throw new Error("No command specified");
  }

  // Validate arguments
  if (options?.validateArgs && !options.validateArgs(args)) {
    throw new Error("Command arguments failed validation");
  }

  // Set default options
  const execOptions: SpawnOptions = {
    cwd: options?.cwd,
    env: options?.env,
    timeout: options?.timeout ?? 30000, // Default 30 seconds
    maxBuffer: options?.maxBuffer ?? 1024 * 1024, // Default 1MB
    shell: false, // Don't use shell for better security
  };

  try {
    const { spawn } = require("child_process");
    const child = spawn(args[0], args.slice(1), execOptions);

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    await new Promise<void>((resolve, reject) => {
      child.on("close", (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Command failed with code ${code}`));
        }
      });

      child.on("error", (err) => {
        reject(err);
      });
    });

    return { stdout, stderr };
  } catch (error) {
    // Don't leak sensitive information in error messages
    throw new Error("Command execution failed");
  }
}

/**
 * Execute a command with arguments safely.
 */
export async function safeExecWithArgs(
  cmd: string,
  args: string[],
  options?: SafeExecOptions
): Promise<{ stdout: string; stderr: string }> {
  // Validate the command
  if (!validateCommand(cmd)) {
    throw new Error("Invalid or dangerous command");
  }

  // Validate arguments
  for (const arg of args) {
    if (!validateArgument(arg)) {
      throw new Error(`Invalid argument: ${arg}`);
    }
  }

  // Set default options
  const execOptions: SpawnOptions = {
    cwd: options?.cwd,
    env: options?.env,
    timeout: options?.timeout ?? 30000,
    maxBuffer: options?.maxBuffer ?? 1024 * 1024,
    shell: false,
  };

  try {
    const { spawn } = require("child_process");
    const child = spawn(cmd, args, execOptions);

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    await new Promise<void>((resolve, reject) => {
      child.on("close", (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`Command failed with code ${code}`));
        }
      });

      child.on("error", (err) => {
        reject(err);
      });
    });

    return { stdout, stderr };
  } catch (error) {
    throw new Error("Command execution failed");
  }
}

/**
 * Parse a command string into arguments safely.
 */
export function parseCommandArgs(command: string): string[] {
  // Remove dangerous characters
  const sanitized = sanitizeCommand(command);
  
  // Split by whitespace
  return sanitized.split(/\s+/).filter((arg) => arg.length > 0);
}

/**
 * Validate a single argument.
 */
export function validateArgument(arg: string): boolean {
  if (typeof arg !== "string" || arg.length === 0) {
    return false;
  }

  // Check for dangerous characters
  if (containsDangerousShellChars(arg)) {
    return false;
  }

  // Check length
  if (arg.length > 1024) {
    return false;
  }

  // Check for path traversal
  if (containsPathTraversal(arg)) {
    return false;
  }

  return true;
}

// --------------------------------------------------------------------------
// Command Whitelist
// --------------------------------------------------------------------------

/**
 * Check if a command is in the allowed whitelist.
 */
export function isCommandAllowed(command: string, allowedCommands: string[]): boolean {
  if (allowedCommands.length === 0) {
    return false;
  }

  const normalizedCommand = command.trim().toLowerCase();
  
  for (const allowed of allowedCommands) {
    const normalizedAllowed = allowed.trim().toLowerCase();
    
    if (normalizedCommand === normalizedAllowed) {
      return true;
    }
  }

  return false;
}

/**
 * Create a command whitelist validator.
 */
export function createCommandWhitelistValidator(allowedCommands: string[]) {
  return (command: string): boolean => {
    if (!validateCommand(command)) {
      return false;
    }

    const args = parseCommandArgs(command);
    if (args.length === 0) {
      return false;
    }

    const commandName = args[0];
    return isCommandAllowed(commandName, allowedCommands);
  };
}
