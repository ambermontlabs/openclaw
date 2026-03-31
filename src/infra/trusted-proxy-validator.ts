/**
 * Trusted Proxy Validator for OpenCLAW
 * Ensures TRUSTED_ENV_PROXY mode is only enabled in trusted environments
 */

// ============================================================================
// Trusted Proxy Validator Class
// ============================================================================

export class TrustedProxyValidator {
  private static readonly ALLOWED_PROXY_HOSTS = new Set([
    'localhost',
    '127.0.0.1',
    '::1', // IPv6 localhost
  ]);

  private static readonly ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

  /**
   * Validate a proxy URL
   */
  static validateProxyUrl(url: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check if URL is empty
    if (!url || url.trim().length === 0) {
      errors.push('Proxy URL cannot be empty');
      return { valid: false, errors };
    }

    // Parse the URL
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(url);
    } catch (error) {
      errors.push('Invalid proxy URL format');
      return { valid: false, errors };
    }

    // Check protocol
    if (!this.ALLOWED_PROTOCOLS.has(parsedUrl.protocol)) {
      errors.push(`Protocol '${parsedUrl.protocol}' is not allowed. Only http and https are allowed.`);
    }

    // Check host
    const hostname = parsedUrl.hostname;
    if (!this.ALLOWED_PROXY_HOSTS.has(hostname)) {
      errors.push(`Proxy host '${hostname}' is not in the allowlist. Only localhost proxies are allowed.`);
    }

    // Check port
    const port = parsedUrl.port || (parsedUrl.protocol === 'https:' ? '443' : '80');
    const portNum = parseInt(port, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      errors.push('Invalid port number');
    }

    // Check for path traversal in URL
    if (parsedUrl.pathname.includes('..')) {
      errors.push('Path contains traversal sequences');
    }

    // Check URL length
    if (url.length > 2048) {
      errors.push('Proxy URL too long');
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Check if a host is in the allowlist
   */
  static isHostAllowed(hostname: string): boolean {
    return this.ALLOWED_PROXY_HOSTS.has(hostname);
  }

  /**
   * Check if a protocol is allowed
   */
  static isProtocolAllowed(protocol: string): boolean {
    return this.ALLOWED_PROTOCOLS.has(protocol);
  }

  /**
   * Validate proxy configuration
   */
  static validateProxyConfig(config: {
    enabled?: boolean;
    url?: string;
    mode?: 'strict' | 'trusted_env_proxy';
  }): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // If proxy is disabled, no validation needed
    if (!config.enabled) {
      return { valid: true, errors };
    }

    // Check mode
    if (config.mode === 'trusted_env_proxy') {
      // In trusted env proxy mode, URL must be provided
      if (!config.url) {
        errors.push('Proxy URL is required in trusted_env_proxy mode');
      } else {
        // Validate the proxy URL
        const urlValidation = this.validateProxyUrl(config.url);
        if (!urlValidation.valid) {
          errors.push(...urlValidation.errors);
        }
      }
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Get allowed proxy hosts
   */
  static getAllowedHosts(): Set<string> {
    return this.ALLOWED_PROXY_HOSTS;
  }

  /**
   * Add allowed host
   */
  static addAllowedHost(hostname: string): void {
    this.ALLOWED_PROXY_HOSTS.add(hostname);
  }

  /**
   * Remove allowed host
   */
  static removeAllowedHost(hostname: string): void {
    this.ALLOWED_PROXY_HOSTS.delete(hostname);
  }
}

// ============================================================================
// Proxy Configuration Validator
// ============================================================================

export class ProxyConfigValidator {
  /**
   * Validate proxy configuration from environment variables
   */
  static validateEnvProxyConfig(env: NodeJS.ProcessEnv): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check if proxy is enabled
    const proxyEnabled = env.OPENCLAW_PROXY_ENABLED === 'true';

    if (proxyEnabled) {
      const proxyUrl = env.OPENCLAW_PROXY_URL;

      if (!proxyUrl) {
        errors.push('OPENCLAW_PROXY_URL is required when proxy is enabled');
      } else {
        // Validate the proxy URL
        const urlValidation = TrustedProxyValidator.validateProxyUrl(proxyUrl);
        if (!urlValidation.valid) {
          errors.push(...urlValidation.errors);
        }
      }

      // Check for insecure proxy settings
      if (env.OPENCLAW_PROXY_INSECURE === 'true') {
        errors.push('Insecure proxy mode is not allowed');
      }
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Validate proxy configuration from config file
   */
  static validateConfigProxyConfig(config: {
    enabled?: boolean;
    url?: string;
    insecure?: boolean;
  }): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (config.enabled) {
      if (!config.url) {
        errors.push('Proxy URL is required when proxy is enabled');
      } else {
        const urlValidation = TrustedProxyValidator.validateProxyUrl(config.url);
        if (!urlValidation.valid) {
          errors.push(...urlValidation.errors);
        }
      }

      if (config.insecure) {
        errors.push('Insecure proxy mode is not allowed');
      }
    }

    return { valid: errors.length === 0, errors };
  }
}

// ============================================================================
// Proxy Auditor
// ============================================================================

export class ProxyAuditor {
  private static auditLog: Array<{
    timestamp: string;
    url?: string;
    valid: boolean;
    errors?: string[];
  }> = [];

  /**
   * Log a proxy validation
   */
  static log(url?: string, valid: boolean = false, errors?: string[]): void {
    const auditEntry = {
      timestamp: new Date().toISOString(),
      url,
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
      console.warn(`Proxy validation failed: ${JSON.stringify(auditEntry)}`);
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
