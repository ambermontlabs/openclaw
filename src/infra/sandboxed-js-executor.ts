/**
 * Sandboxed JavaScript Executor for OpenCLAW
 * Prevents arbitrary code execution via canvas.eval
 */

// ============================================================================
// Sandboxed JS Executor Class
// ============================================================================

export class SandboxedJSExecutor {
  private static readonly MAX_CODE_LENGTH = 1000;
  private static readonly MAX_TIMEOUT_MS = 5000;
  private static readonly ALLOWED_GLOBALS = new Set([
    'console',
    'Math',
    'Date',
    'Array',
    'Object',
    'String',
    'Number',
    'Boolean',
    'Infinity',
    'NaN',
    'undefined',
    'null',
  ]);

  private static readonly BLOCKED_PATTERNS = [
    // Import statements
    /import\s+.*\s+from\s+/,
    /require\s*\(/,

    // Fetch and network
    /fetch\s*\(/,
    /XMLHttpRequest/,
    /WebSocket/,

    // Process access
    /process\./,
    /__dirname/,
    /__filename/,

    // Eval and dynamic execution
    /eval\s*\(/,
    /new\s+Function\s*\(/,

    // File system access
    /fs\./,
    /require\s*['"]fs['"]/,

    // DOM manipulation (in Node.js context)
    /document\./,
    /window\./,

    // Dangerous APIs
    /setTimeout\s*\(\s*eval/,
    /setInterval\s*\(\s*eval/,

    // Function constructor
    /Function\s*\(/,
  ];

  /**
   * Execute JavaScript code in a sandboxed environment
   */
  static async execute(
    code: string,
    context?: Record<string, unknown>,
    options?: {
      timeoutMs?: number;
      maxMemoryMB?: number;
    }
  ): Promise<unknown> {
    // Validate input
    const validation = this.validateCode(code);
    if (!validation.valid) {
      throw new Error(`Invalid code: ${validation.errors.join(', ')}`);
    }

    // Set timeout
    const timeoutMs = options?.timeoutMs || this.MAX_TIMEOUT_MS;
    if (timeoutMs > this.MAX_TIMEOUT_MS) {
      throw new Error(`Timeout cannot exceed ${this.MAX_TIMEOUT_MS}ms`);
    }

    // Create a safe context
    const safeContext = this.createSafeContext(context);

    try {
      // Create a new context with limited globals
      const vm = await import('node:vm');
      
      const sandbox = {
        ...safeContext,
        console: this.sanitizeConsole(console),
        require: null, // Disable require
        module: {},
        exports: {},
      };

      const contextObj = vm.createContext(sandbox);

      // Create a wrapper function
      const wrappedCode = `(function() { ${code} })`;

      // Execute with timeout
      let result: unknown;
      const timer = setTimeout(() => {
        throw new Error('Execution timeout');
      }, timeoutMs);

      try {
        const script = new vm.Script(wrappedCode);
        result = script.runInContext(contextObj, {
          timeout: timeoutMs,
          displayErrors: true,
        });
      } finally {
        clearTimeout(timer);
      }

      // Sanitize result
      return this.sanitizeResult(result);

    } catch (error) {
      throw new Error(`Execution failed: ${error}`);
    }
  }

  /**
   * Validate JavaScript code
   */
  private static validateCode(code: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check length
    if (code.length > this.MAX_CODE_LENGTH) {
      errors.push(`Code exceeds maximum length of ${this.MAX_CODE_LENGTH} characters`);
    }

    // Check for blocked patterns
    for (const pattern of this.BLOCKED_PATTERNS) {
      if (pattern.test(code)) {
        errors.push('Code contains blocked patterns');
        break;
      }
    }

    // Check for dangerous characters
    if (code.includes('`') && !code.startsWith('`') && !code.endsWith('`')) {
      errors.push('Template literals not allowed');
    }

    // Check for control characters
    if (/[\x00-\x1F\x7F]/.test(code)) {
      errors.push('Control characters not allowed');
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Create a safe context
   */
  private static createSafeContext(context?: Record<string, unknown>): Record<string, unknown> {
    const safeContext: Record<string, unknown> = {};

    // Only allow whitelisted globals
    for (const [key, value] of Object.entries(global)) {
      if (this.ALLOWED_GLOBALS.has(key)) {
        safeContext[key] = value;
      }
    }

    // Add custom context (sanitized)
    if (context) {
      for (const [key, value] of Object.entries(context)) {
        if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
          safeContext[key] = this.sanitizeValue(value);
        }
      }
    }

    return safeContext;
  }

  /**
   * Sanitize console object
   */
  private static sanitizeConsole(originalConsole: Console): Console {
    const safeConsole = { ...originalConsole };

    // Override console methods to sanitize output
    for (const method of ['log', 'info', 'warn', 'error', 'debug']) {
      if (typeof originalConsole[method] === 'function') {
        safeConsole[method] = (...args: unknown[]) => {
          const sanitizedArgs = args.map(arg => this.sanitizeValue(arg));
          originalConsole[method](...sanitizedArgs);
        };
      }
    }

    return safeConsole as Console;
  }

  /**
   * Sanitize a value
   */
  private static sanitizeValue(value: unknown): unknown {
    if (typeof value === 'string') {
      // Truncate long strings
      if (value.length > 1000) {
        return value.substring(0, 1000) + '...';
      }
      return value;
    }

    if (typeof value === 'object' && value !== null) {
      // Only allow simple objects
      if (Array.isArray(value)) {
        return value.map(item => this.sanitizeValue(item));
      }

      const sanitized: Record<string, unknown> = {};
      let count = 0;

      for (const [key, val] of Object.entries(value)) {
        if (count >= 100) {
          break;
        }
        sanitized[key] = this.sanitizeValue(val);
        count++;
      }

      return sanitized;
    }

    return value;
  }

  /**
   * Sanitize result
   */
  private static sanitizeResult(result: unknown): unknown {
    // Remove functions and symbols from result
    if (typeof result === 'function') {
      return '[Function]';
    }

    if (typeof result === 'symbol') {
      return String(result);
    }

    if (typeof result === 'object' && result !== null) {
      const sanitized: Record<string, unknown> = {};

      for (const [key, val] of Object.entries(result)) {
        if (!key.startsWith('_') && typeof result[key] !== 'function') {
          sanitized[key] = this.sanitizeResult(result[key]);
        }
      }

      return sanitized;
    }

    return result;
  }

  /**
   * Check if code is safe to execute
   */
  static isCodeSafe(code: string): boolean {
    return this.validateCode(code).valid;
  }

  /**
   * Get allowed globals
   */
  static getAllowedGlobals(): Set<string> {
    return this.ALLOWED_GLOBALS;
  }

  /**
   * Get blocked patterns
   */
  static getBlockedPatterns(): RegExp[] {
    return this.BLOCKED_PATTERNS;
  }
}

// ============================================================================
// Canvas Execution Validator
// ============================================================================

export class CanvasExecutionValidator {
  private static readonly ALLOWED_OPERATORS = new Set([
    '+', '-', '*', '/', '%', '===', '!==', '==', '!=',
    '<', '>', '<=', '>=', '&&', '||', '!', '??',
    '++', '--', '+=', '-=', '*=', '/=', '%=',
  ]);

  private static readonly ALLOWED_KEYWORDS = new Set([
    'if', 'else', 'for', 'while', 'return', 'var', 'let', 'const',
    'true', 'false', 'null', 'undefined', 'function', 'class',
  ]);

  /**
   * Validate canvas execution code
   */
  static validateCanvasCode(code: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // First check with SandboxedJSExecutor
    const sandboxValidation = SandboxedJSExecutor.validateCode(code);
    if (!sandboxValidation.valid) {
      errors.push(...sandboxValidation.errors);
      return { valid: false, errors };
    }

    // Additional canvas-specific checks
    if (code.includes('document') || code.includes('window')) {
      errors.push('DOM manipulation not allowed in canvas execution');
    }

    if (code.includes('fetch') || code.includes('XMLHttpRequest')) {
      errors.push('Network requests not allowed in canvas execution');
    }

    if (code.includes('localStorage') || code.includes('sessionStorage')) {
      errors.push('Storage access not allowed in canvas execution');
    }

    return { valid: errors.length === 0, errors };
  }
}

// ============================================================================
// Canvas Execution Auditor
// ============================================================================

export class CanvasExecutionAuditor {
  private static auditLog: Array<{
    timestamp: string;
    codePreview?: string;
    valid: boolean;
    errors?: string[];
  }> = [];

  /**
   * Log a canvas execution
   */
  static log(
    code: string,
    valid: boolean,
    errors?: string[]
  ): void {
    const auditEntry = {
      timestamp: new Date().toISOString(),
      codePreview: code.length > 100 ? `${code.substring(0, 100)}...` : code,
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
      console.warn(`Canvas execution blocked: ${JSON.stringify(auditEntry)}`);
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
