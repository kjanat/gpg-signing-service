/**
 * Type-safe D1 database utilities
 */

import { z } from "@hono/zod-openapi";
import type { AuditAction, AuditLogEntry } from "~/schemas/audit";
import type { ErrorCode } from "~/schemas/errors";

/**
 * D1 row schema for audit_logs table
 */
const D1AuditLogRowSchema = z.object({
  id: z.string(),
  timestamp: z.string(),
  request_id: z.string(),
  action: z.string(),
  issuer: z.string(),
  subject: z.string(),
  key_id: z.string(),
  success: z.union([z.number(), z.boolean()]), // D1 returns 0/1 for boolean
  error_code: z.string().nullable(),
  metadata: z.string().nullable(),
});

/**
 * Transform D1 row to domain model
 */
export function transformAuditLogRow(row: unknown): AuditLogEntry {
  const parsed = D1AuditLogRowSchema.parse(row);

  return {
    id: parsed.id,
    timestamp: parsed.timestamp,
    requestId: parsed.request_id,
    action: parsed.action as AuditAction,
    issuer: parsed.issuer,
    subject: parsed.subject,
    keyId: parsed.key_id,
    success: Boolean(parsed.success),
    errorCode: parsed.error_code as ErrorCode | undefined,
    metadata: parsed.metadata || undefined,
  };
}

/**
 * Type-safe D1 query builder
 */
export class D1QueryBuilder {
  private conditions: string[] = [];
  private params: (string | number)[] = [];
  private query: string;

  constructor(baseQuery: string) {
    this.query = baseQuery;
  }

  where(column: string, value: string | number): this {
    this.conditions.push(`${column} = ?`);
    this.params.push(value);
    return this;
  }

  whereBetween(column: string, start: string, end: string): this {
    this.conditions.push(`${column} BETWEEN ? AND ?`);
    this.params.push(start, end);
    return this;
  }

  orderBy(column: string, direction: "ASC" | "DESC" = "DESC"): this {
    this.query += ` ORDER BY ${column} ${direction}`;
    return this;
  }

  limit(limit: number, offset = 0): this {
    this.query += ` LIMIT ? OFFSET ?`;
    this.params.push(limit, offset);
    return this;
  }

  build(): { query: string; params: (string | number)[] } {
    if (this.conditions.length > 0) {
      this.query += ` WHERE ${this.conditions.join(" AND ")}`;
    }
    return { query: this.query, params: this.params };
  }

  async execute<T>(
    db: D1Database,
    transformer?: (row: unknown) => T,
  ): Promise<T[]> {
    const { query, params } = this.build();
    const result = await db
      .prepare(query)
      .bind(...params)
      .all();

    if (!result.results) return [];

    return transformer
      ? result.results.map(transformer)
      : (result.results as T[]);
  }
}
