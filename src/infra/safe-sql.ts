/**
 * Safe SQL for OpenCLAW
 * Prevents SQL injection by using parameterized queries and validation
 */

// ============================================================================
// Safe SQL Builder Class
// ============================================================================

export class SafeSQL {
  private static readonly ALLOWED_OPERATORS = new Set([
    '=', '!=', '<', '>', '<=', '>=',
    'LIKE', 'NOT LIKE', 'IN', 'NOT IN', 'BETWEEN', 'IS NULL', 'IS NOT NULL',
  ]);

  private static readonly ALLOWED_LOGICAL_OPERATORS = new Set(['AND', 'OR']);

  /**
   * Build a SELECT query with parameterized values
   */
  static buildSelect(
    table: string,
    columns: string[],
    conditions?: Record<string, unknown>,
    options?: {
      limit?: number;
      offset?: number;
      orderBy?: string[];
      groupBy?: string[];
    }
  ): { query: string; params: unknown[] } {
    const columnsStr = this.sanitizeColumns(columns);
    let query = `SELECT ${columnsStr} FROM ${this.sanitizeIdentifier(table)}`;
    const params: unknown[] = [];

    if (conditions && Object.keys(conditions).length > 0) {
      const conditionParts: string[] = [];
      
      for (const [column, value] of Object.entries(conditions)) {
        const sanitizedColumn = this.sanitizeIdentifier(column);
        
        if (value === null) {
          conditionParts.push(`${sanitizedColumn} IS NULL`);
        } else if (value === undefined) {
          // Skip undefined values
          continue;
        } else if (Array.isArray(value)) {
          // IN clause
          const placeholders = value.map(() => '?').join(', ');
          conditionParts.push(`${sanitizedColumn} IN (${placeholders})`);
          params.push(...value);
        } else {
          // Regular equality
          conditionParts.push(`${sanitizedColumn} = ?`);
          params.push(value);
        }
      }

      if (conditionParts.length > 0) {
        query += ` WHERE ${conditionParts.join(' AND ')}`;
      }
    }

    if (options?.groupBy) {
      const groupByStr = options.groupBy.map(col => this.sanitizeIdentifier(col)).join(', ');
      query += ` GROUP BY ${groupByStr}`;
    }

    if (options?.orderBy) {
      const orderByStr = options.orderBy.map(col => this.sanitizeIdentifier(col)).join(', ');
      query += ` ORDER BY ${orderByStr}`;
    }

    if (options?.limit !== undefined) {
      query += ` LIMIT ?`;
      params.push(options.limit);
    }

    if (options?.offset !== undefined) {
      query += ` OFFSET ?`;
      params.push(options.offset);
    }

    return { query, params };
  }

  /**
   * Build an INSERT query
   */
  static buildInsert(
    table: string,
    data: Record<string, unknown>
  ): { query: string; params: unknown[] } {
    const columns = Object.keys(data);
    const placeholders = columns.map(() => '?').join(', ');
    
    return {
      query: `INSERT INTO ${this.sanitizeIdentifier(table)} (${columns.map(col => this.sanitizeIdentifier(col)).join(', ')}) VALUES (${placeholders})`,
      params: Object.values(data),
    };
  }

  /**
   * Build an UPDATE query
   */
  static buildUpdate(
    table: string,
    data: Record<string, unknown>,
    conditions: Record<string, unknown>
  ): { query: string; params: unknown[] } {
    const setParts: string[] = [];
    const params: unknown[] = [];

    // Add data values first
    for (const [column, value] of Object.entries(data)) {
      const sanitizedColumn = this.sanitizeIdentifier(column);
      setParts.push(`${sanitizedColumn} = ?`);
      params.push(value);
    }

    // Add conditions
    for (const [column, value] of Object.entries(conditions)) {
      const sanitizedColumn = this.sanitizeIdentifier(column);
      
      if (value === null) {
        setParts.push(`${sanitizedColumn} = ?`);
        params.push(null);
      } else {
        setParts.push(`${sanitizedColumn} = ?`);
        params.push(value);
      }
    }

    return {
      query: `UPDATE ${this.sanitizeIdentifier(table)} SET ${setParts.join(', ')}`,
      params,
    };
  }

  /**
   * Build a DELETE query
   */
  static buildDelete(
    table: string,
    conditions?: Record<string, unknown>
  ): { query: string; params: unknown[] } {
    let query = `DELETE FROM ${this.sanitizeIdentifier(table)}`;
    const params: unknown[] = [];

    if (conditions && Object.keys(conditions).length > 0) {
      const conditionParts: string[] = [];
      
      for (const [column, value] of Object.entries(conditions)) {
        const sanitizedColumn = this.sanitizeIdentifier(column);
        
        if (value === null) {
          conditionParts.push(`${sanitizedColumn} IS NULL`);
        } else if (value === undefined) {
          continue;
        } else {
          conditionParts.push(`${sanitizedColumn} = ?`);
          params.push(value);
        }
      }

      if (conditionParts.length > 0) {
        query += ` WHERE ${conditionParts.join(' AND ')}`;
      }
    }

    return { query, params };
  }

  /**
   * Sanitize a column/identifier name
   */
  private static sanitizeIdentifier(identifier: string): string {
    // Only allow alphanumeric, underscores, and dots (for table.column)
    if (!/^[a-zA-Z_][a-zA-Z0-9_.]*$/.test(identifier)) {
      throw new Error(`Invalid identifier: ${identifier}`);
    }

    // Escape dots for table.column format
    return identifier.replace(/\./g, '`.`');
  }

  /**
   * Sanitize column list
   */
  private static sanitizeColumns(columns: string[]): string {
    return columns.map(col => this.sanitizeIdentifier(col)).join(', ');
  }

  /**
   * Validate a WHERE clause condition
   */
  static validateCondition(column: string, operator: string, value: unknown): boolean {
    // Validate column name
    if (!/^[a-zA-Z_][a-zA-Z0-9_.]*$/.test(column)) {
      return false;
    }

    // Validate operator
    if (!this.ALLOWED_OPERATORS.has(operator.toUpperCase())) {
      return false;
    }

    // Validate value based on operator
    if (operator.toUpperCase() === 'LIKE') {
      // LIKE values can contain wildcards
      return typeof value === 'string';
    }

    if (operator.toUpperCase() === 'IN') {
      // IN values must be an array
      return Array.isArray(value);
    }

    if (operator.toUpperCase() === 'BETWEEN') {
      // BETWEEN values must be an array with 2 elements
      return Array.isArray(value) && value.length === 2;
    }

    if (operator.toUpperCase() === 'IS NULL' || operator.toUpperCase() === 'IS NOT NULL') {
      // These operators don't need values
      return value === undefined || value === null;
    }

    // Regular operators need a value
    return value !== undefined && value !== null;
  }
}

// ============================================================================
// SQL Query Validator
// ============================================================================

export class SqlQueryValidator {
  private static readonly BLOCKED_KEYWORDS = [
    'DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'CREATE', 'UPDATE',
    '--', '/*', '*/', ';', '\n', '\r',
  ];

  /**
   * Validate a raw SQL query
   */
  static validateQuery(query: string): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Check for blocked keywords
    for (const keyword of this.BLOCKED_KEYWORDS) {
      if (query.toUpperCase().includes(keyword)) {
        errors.push(`Blocked keyword detected: ${keyword}`);
      }
    }

    // Check for multiple statements
    if (query.split(';').length > 1) {
      errors.push('Multiple statements are not allowed');
    }

    // Check for comments
    if (query.includes('--') || query.includes('/*')) {
      errors.push('Comments are not allowed in queries');
    }

    // Check for dangerous patterns
    const dangerousPatterns = [
      /exec\s*\(/i,
      /system\s*\(/i,
      /shell_exec\s*\(/i,
      /eval\s*\(/i,
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(query)) {
        errors.push('Dangerous pattern detected in query');
        break;
      }
    }

    return { valid: errors.length === 0, errors };
  }

  /**
   * Sanitize a raw SQL query
   */
  static sanitizeQuery(query: string): string {
    // Remove comments
    let sanitized = query.replace(/--.*$/gm, '');
    sanitized = sanitized.replace(/\/\*[\s\S]*?\*\//g, '');

    // Remove multiple statements
    sanitized = sanitized.split(';')[0];

    return sanitized.trim();
  }
}

// ============================================================================
// SQL Query Builder
// ============================================================================

export class SqlQueryBuilder {
  /**
   * Build a parameterized query from parts
   */
  static buildQuery(
    table: string,
    columns: string[],
    conditions?: Record<string, unknown>,
    options?: {
      limit?: number;
      offset?: number;
      orderBy?: string[];
      groupBy?: string[];
    }
  ): { query: string; params: unknown[] } {
    return SafeSQL.buildSelect(table, columns, conditions, options);
  }

  /**
   * Build a query with custom WHERE clause
   */
  static buildCustomQuery(
    table: string,
    columns: string[],
    whereClause: string,
    params: unknown[]
  ): { query: string; params: unknown[] } {
    // Validate where clause
    if (!SqlQueryValidator.validateQuery(whereClause).valid) {
      throw new Error('Invalid WHERE clause');
    }

    return {
      query: `SELECT ${columns.map(col => SafeSQL.sanitizeIdentifier(col)).join(', ')} FROM ${SafeSQL.sanitizeIdentifier(table)} WHERE ${whereClause}`,
      params,
    };
  }
}
