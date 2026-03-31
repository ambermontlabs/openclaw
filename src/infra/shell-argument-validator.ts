/**
 * Shell Argument Validator for OpenCLAW
 * Prevents command injection in shell wrapper commands
 */

// ============================================================================
// Allowed Commands and Flags
// ============================================================================

export const ALLOWED_COMMANDS = new Set([
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

// Allowed flags for each command
export const ALLOWED_FLAGS: Record<string, Set<string>> = {
  echo: new Set(['-n', '-e']),
  cat: new Set(['-n', '-T', '-s', '-A']),
  ls: new Set(['-l', '-a', '-h', '-t', '-r', '-S', '-R']),
  grep: new Set(['-i', '-v', '-n', '-c', '-E', '-F', 'e']),
  sed: new Set(['-e', '-i', 's///']),
  awk: new Set(['-F', '-v', '-f']),
  head: new Set(['-n', '-c']),
  tail: new Set(['-n', '-f', '-c']),
};

// ============================================================================
// Shell Argument Validator Class
// ============================================================================

export class ShellArgumentValidator {
  private static readonly MAX_ARG_LENGTH = 256;
  private static readonly MAX_ARGS_COUNT = 100;

  /**
   * Validate a command and its arguments
   */
  static validate(command: string, args: string[]): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check command is in allowlist
    if (!ALLOWED_COMMANDS.has(command)) {
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

    // Validate each argument
    for (const arg of args) {
      const argErrors = this.validateArgument(arg);
      errors.push(...argErrors);
    }

    // Validate flag combinations for specific commands
    if (ALLOWED_FLAGS[command]) {
      const flagErrors = this.validateFlags(command, args);
      errors.push(...flagErrors);
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Validate a single argument
   */
  private static validateArgument(arg: string): string[] {
    const errors: string[] = [];

    // Check length
    if (arg.length > this.MAX_ARG_LENGTH) {
      errors.push(`Argument too long: maximum ${this.MAX_ARG_LENGTH} characters`);
    }

    // Check for dangerous patterns
    if (this.hasDangerousPatterns(arg)) {
      errors.push(`Argument contains dangerous patterns: ${arg}`);
    }

    // Check for path traversal
    if (this.hasPathTraversal(arg)) {
      errors.push(`Argument contains path traversal: ${arg}`);
    }

    // Check for command substitution
    if (this.hasCommandSubstitution(arg)) {
      errors.push(`Argument contains command substitution: ${arg}`);
    }

    // Check for shell metacharacters
    if (this.hasShellMetacharacters(arg)) {
      errors.push(`Argument contains shell metacharacters: ${arg}`);
    }

    // Check for unsafe characters
    if (!this.isSafeArgument(arg)) {
      errors.push(`Argument contains unsafe characters: ${arg}`);
    }

    return errors;
  }

  /**
   * Check if command name is valid
   */
  private static isValidCommandName(command: string): boolean {
    // Only allow alphanumeric, hyphens, and underscores
    return /^[a-zA-Z][a-zA-Z0-9\-_]*$/.test(command);
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
   * Validate flags for a specific command
   */
  private static validateFlags(command: string, args: string[]): string[] {
    const errors: string[] = [];
    const allowedFlags = ALLOWED_FLAGS[command];

    if (!allowedFlags) {
      return errors;
    }

    for (const arg of args) {
      if (arg.startsWith('-') && !allowedFlags.has(arg)) {
        errors.push(`Flag '${arg}' not allowed for command '${command}'`);
      }
    }

    return errors;
  }

  /**
   * Sanitize an argument by removing dangerous characters
   */
  static sanitizeArgument(arg: string): string {
    // Remove command substitution
    let sanitized = arg.replace(/\$\([^)]*\)/g, '');
    sanitized = sanitized.replace(/`[^`]*`/g, '');

    // Remove variable expansion
    sanitized = sanitized.replace(/\$[a-zA-Z_][a-zA-Z0-9_]*/g, '');

    // Remove dangerous characters
    const dangerous = [';', '|', '&', '>', '<', '(', ')'];
    for (const char of dangerous) {
      sanitized = sanitized.split(char).join('');
    }

    return sanitized;
  }
}

// ============================================================================
// Shell Command Auditor
// ============================================================================

export class ShellCommandAuditor {
  private static auditLog: Array<{
    timestamp: string;
    command: string;
    args: string[];
    valid: boolean;
    errors?: string[];
  }> = [];

  /**
   * Log a shell command execution
   */
  static log(command: string, args: string[], valid: boolean, errors?: string[]): void {
    const auditEntry = {
      timestamp: new Date().toISOString(),
      command,
      args: args.map(a => a.length > 50 ? `${a.substring(0, 50)}...` : a),
      valid,
      errors: errors?.length ? errors : undefined,
    };

    this.auditLog.push(auditEntry);

    // Keep only last 1000 entries
    if (this.auditLog.length > 1000) {
      this.auditLog.shift();
    }

    // Log to console for debugging
    if (!valid) {
      console.warn(`Shell command blocked: ${JSON.stringify(auditEntry)}`);
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
