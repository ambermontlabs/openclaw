/**
 * System Run Command Allowlist for OpenCLAW
 * Prevents unauthorized command execution via system.run
 */

// ============================================================================
// System Run Command Allowlist
// ============================================================================

export const SYSTEM_RUN_COMMAND_ALLOWLIST = new Set([
  // Basic system commands
  'echo',
  'cat',
  'ls',
  'pwd',
  'date',
  'whoami',
  'uname',
  'hostname',
  'uptime',
  'df',
  'du',
  'top',
  'ps',

  // File operations
  'cp',
  'mv',
  'rm',
  'mkdir',
  'touch',
  'chmod',
  'chown',

  // Text processing
  'grep',
  'sed',
  'awk',
  'cut',
  'sort',
  'uniq',
  'wc',
  'head',
  'tail',
  'tr',
  'fold',
  'paste',

  // Network utilities (limited)
  'ping',
  'curl',
  'wget',
  'nc',

  // Compression
  'tar',
  'gzip',
  'gunzip',
  'unzip',
  'zip',

  // System info
  'env',
  'export',
  'printenv',
]);

// ============================================================================
// Command Policy Definitions
// ============================================================================

export interface SystemRunCommandPolicy {
  command: string;
  allowedArgs?: RegExp[];
  requireApproval?: boolean;
  maxArgs?: number;
}

export const SYSTEM_RUN_COMMAND_POLICIES: Record<string, SystemRunCommandPolicy> = {
  // Commands that require approval
  'curl': {
    command: 'curl',
    requireApproval: true,
    allowedArgs: [/^https?:\/\//, /^-/, /^--/],
  },
  'wget': {
    command: 'wget',
    requireApproval: true,
    allowedArgs: [/^https?:\/\//, /^-/, /^--/],
  },
  'rm': {
    command: 'rm',
    requireApproval: true,
    allowedArgs: [/^-/, /^--/],
  },
  'chmod': {
    command: 'chmod',
    requireApproval: true,
    allowedArgs: [/^[0-7]+$/, /^-/, /^--/],
  },
  'chown': {
    command: 'chown',
    requireApproval: true,
    allowedArgs: [/^[^:]+:[^:]+$/, /^-/, /^--/],
  },
  'env': {
    command: 'env',
    requireApproval: true,
    allowedArgs: [/^[A-Z_][A-Z0-9_]*=/, /^-/, /^--/],
  },
};

// ============================================================================
// System Run Command Validator
// ============================================================================

export class SystemRunCommandValidator {
  private static readonly MAX_ARGS_COUNT = 100;
  private static readonly MAX_ARG_LENGTH = 256;

  /**
   * Validate a system run command
   */
  static validate(
    command: string,
    args: string[]
  ): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check if command is in allowlist
    if (!SYSTEM_RUN_COMMAND_ALLOWLIST.has(command)) {
      errors.push(`Command '${command}' is not in the allowlist`);
    }

    // Validate command format
    if (!this.isValidCommandName(command)) {
      errors.push(`Invalid command name: ${command}`);
    }

    // Validate arguments count
    if (args.length > this.MAX_ARGS_COUNT) {
      errors.push(`Too many arguments: maximum ${this.MAX_ARGS_COUNT} allowed`);
    }

    // Get command-specific policy
    const policy = SYSTEM_RUN_COMMAND_POLICIES[command];

    // Validate each argument
    for (const arg of args) {
      const argErrors = this.validateArgument(arg, policy);
      errors.push(...argErrors);
    }

    // Validate argument count for specific commands
    if (policy?.maxArgs && args.length > policy.maxArgs) {
      errors.push(`Command '${command}' accepts at most ${policy.maxArgs} arguments`);
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Check if command name is valid
   */
  private static isValidCommandName(command: string): boolean {
    // Only allow alphanumeric, hyphens, and underscores
    return /^[a-zA-Z][a-zA-Z0-9\-_]*$/.test(command);
  }

  /**
   * Validate a single argument
   */
  private static validateArgument(
    arg: string,
    policy?: SystemRunCommandPolicy
  ): string[] {
    const errors: string[] = [];

    // Check length
    if (arg.length > this.MAX_ARG_LENGTH) {
      errors.push(`Argument too long: maximum ${this.MAX_ARG_LENGTH} characters`);
    }

    // Check for dangerous patterns
    if (this.hasDangerousPatterns(arg)) {
      errors.push(`Argument contains dangerous patterns`);
    }

    // Check for path traversal
    if (this.hasPathTraversal(arg)) {
      errors.push(`Argument contains path traversal`);
    }

    // Check for command substitution
    if (this.hasCommandSubstitution(arg)) {
      errors.push(`Argument contains command substitution`);
    }

    // Check for shell metacharacters
    if (this.hasShellMetacharacters(arg)) {
      errors.push(`Argument contains shell metacharacters`);
    }

    // Check for unsafe characters
    if (!this.isSafeArgument(arg)) {
      errors.push(`Argument contains unsafe characters`);
    }

    // Check against allowed patterns from policy
    if (policy?.allowedArgs) {
      const patternErrors = this.validateAgainstPolicy(arg, policy);
      errors.push(...patternErrors);
    }

    return errors;
  }

  /**
   * Check for dangerous patterns in arguments
   */
  private static hasDangerousPatterns(arg: string): boolean {
    const dangerousPatterns = [
      // Command injection
      /;/,           // Semicolon
      /\|/,          // Pipe
      /&/,           // Ampersand
      /\$\(/,        // Command substitution $
      /\$[a-zA-Z_]/, // Variable expansion
      /`/,           // Backtick

      // Path traversal
      /\.\./,        // Double dot
      /\/\//,        // Double slash

      // URL schemes (except http/https)
      /javascript:/i,
      /data:/i,
      /vbscript:/i,
      /file:/i,

      // SQL injection
      /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER|TRUNCATE)\b/i,
      /--/,          // SQL comment
      /\/\*/,        // Block comment start

      // XSS patterns
      /<script/i,
      /on\w+\s*=/i,  // Event handlers

      // Command execution
      /\b(exec|system|shell_exec|passthru|eval)\s*\(/i,
    ];

    return dangerousPatterns.some(pattern => pattern.test(arg));
  }

  /**
   * Check for path traversal
   */
  private static hasPathTraversal(arg: string): boolean {
    // Check for .. in path
    if (arg.includes('..') && !arg.startsWith('./')) {
      return true;
    }

    // Check for absolute path traversal
    if (arg.startsWith('/')) {
      const parts = arg.split('/');
      for (let i = 0; i < parts.length - 1; i++) {
        if (parts[i] === '..') {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check for command substitution
   */
  private static hasCommandSubstitution(arg: string): boolean {
    // Check for $() syntax
    if (arg.includes('$(')) {
      return true;
    }

    // Check for backtick syntax
    if (arg.includes('`')) {
      return true;
    }

    // Check for variable expansion
    if (arg.includes('$') && !arg.startsWith('$')) {
      return true;
    }

    return false;
  }

  /**
   * Check for shell metacharacters
   */
  private static hasShellMetacharacters(arg: string): boolean {
    const metacharacters = [';', '|', '&', '$', '`', '>', '<', '(', ')'];

    return metacharacters.some(char => arg.includes(char));
  }

  /**
   * Check if argument contains only safe characters
   */
  private static isSafeArgument(arg: string): boolean {
    // Only allow alphanumeric, spaces, and safe punctuation
    const safePattern = /^[a-zA-Z0-9_\-./\s\+\-=]*$/;

    return safePattern.test(arg);
  }

  /**
   * Validate against policy patterns
   */
  private static validateAgainstPolicy(
    arg: string,
    policy: SystemRunCommandPolicy
  ): string[] {
    const errors: string[] = [];

    // If no allowed patterns, allow all
    if (!policy.allowedArgs || policy.allowedArgs.length === 0) {
      return errors;
    }

    // Check if argument matches any allowed pattern
    const matches = policy.allowedArgs.some(pattern => pattern.test(arg));

    if (!matches) {
      errors.push(`Argument does not match allowed patterns for '${policy.command}'`);
    }

    return errors;
  }

  /**
   * Check if command requires approval
   */
  static requiresApproval(command: string): boolean {
    const policy = SYSTEM_RUN_COMMAND_POLICIES[command];
    return !!policy?.requireApproval;
  }

  /**
   * Get command policy
   */
  static getPolicy(command: string): SystemRunCommandPolicy | undefined {
    return SYSTEM_RUN_COMMAND_POLICIES[command];
  }
}

// ============================================================================
// System Run Command Auditor
// ============================================================================

export class SystemRunCommandAuditor {
  private static auditLog: Array<{
    timestamp: string;
    command: string;
    args: string[];
    valid: boolean;
    requiresApproval?: boolean;
    errors?: string[];
  }> = [];

  /**
   * Log a system run command validation
   */
  static log(
    command: string,
    args: string[],
    valid: boolean,
    requiresApproval?: boolean,
    errors?: string[]
  ): void {
    const auditEntry = {
      timestamp: new Date().toISOString(),
      command,
      args: args.map(a => (a.length > 50 ? `${a.substring(0, 50)}...` : a)),
      valid,
      requiresApproval,
      errors: errors?.length ? errors : undefined,
    };

    this.auditLog.push(auditEntry);

    // Keep only last 1000 entries
    if (this.auditLog.length > 1000) {
      this.auditLog.shift();
    }

    // Log to console for debugging
    if (!valid) {
      console.warn(`System run command blocked: ${JSON.stringify(auditEntry)}`);
    }
  }

  /**
   * Get audit log
   */
  static getAuditLog(): typeof this.auditLog {
    return this.auditLog;
  }

  /**
   * Clear audit log
   */
  static clearAuditLog(): void {
    this.auditLog = [];
  }
}
