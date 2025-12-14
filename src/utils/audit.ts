import type { AuditAction, AuditLogEntry } from "~/schemas/audit";
import type { ErrorCode } from "~/schemas/errors";

/**
 * Log an audit event to the D1 database.
 *
 * @param db - D1 database binding
 * @param entry - Audit log entry data (id and timestamp are auto-generated)
 *
 * @example
 * ```ts
 * await logAuditEvent(env.AUDIT_DB, {
 *   requestId: "uuid",
 *   action: "sign",
 *   issuer: "https://token.actions.githubusercontent.com",
 *   subject: "owner/repo",
 *   keyId: "signing-key-v1",
 *   success: true,
 * });
 * ```
 */
export async function logAuditEvent(
  db: D1Database,
  entry: Omit<AuditLogEntry, "id" | "timestamp">,
): Promise<void> {
  const id = crypto.randomUUID();
  const timestamp = new Date().toISOString();

  await db
    .prepare(
      `
      INSERT INTO audit_logs (id, timestamp, request_id, action, issuer, subject, key_id, success, error_code, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `,
    )
    .bind(
      id,
      timestamp,
      entry.requestId,
      entry.action,
      entry.issuer,
      entry.subject,
      entry.keyId,
      entry.success ? 1 : 0,
      entry.errorCode || null,
      entry.metadata || null,
    )
    .run();
}

/**
 * Query audit logs from the D1 database with optional filtering.
 *
 * @param db - D1 database binding
 * @param options - Query options for filtering and pagination
 * @param options.limit - Maximum entries to return (default: 100)
 * @param options.offset - Number of entries to skip (default: 0)
 * @param options.action - Filter by action type (sign, key_upload, key_rotate)
 * @param options.subject - Filter by subject (partial match)
 * @param options.startDate - Filter from this date (ISO 8601)
 * @param options.endDate - Filter until this date (ISO 8601)
 * @returns Array of audit log entries, ordered by timestamp descending
 *
 * @example
 * ```ts
 * const logs = await getAuditLogs(env.AUDIT_DB, {
 *   action: "sign",
 *   limit: 50,
 *   startDate: "2024-01-01T00:00:00Z",
 * });
 * ```
 */
export async function getAuditLogs(
  db: D1Database,
  options: {
    limit?: number;
    offset?: number;
    action?: string;
    subject?: string;
    startDate?: string;
    endDate?: string;
  } = {},
): Promise<AuditLogEntry[]> {
  const {
    limit = 100,
    offset = 0,
    action,
    subject,
    startDate,
    endDate,
  } = options;

  let query = "SELECT * FROM audit_logs WHERE 1=1";
  const params: (string | number)[] = [];

  if (action) {
    query += " AND action = ?";
    params.push(action);
  }

  if (subject) {
    // SECURITY: Escape LIKE wildcards to prevent pattern injection (OWASP A03:2021)
    // Must specify ESCAPE clause for SQLite to recognize the escape character
    query += " AND subject LIKE ? ESCAPE '\\'";
    const escapedSubject = subject.replace(/[%_\\]/g, "\\$&");
    params.push(`%${escapedSubject}%`);
  }

  if (startDate) {
    query += " AND timestamp >= ?";
    params.push(startDate);
  }

  if (endDate) {
    query += " AND timestamp <= ?";
    params.push(endDate);
  }

  query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?";
  params.push(limit, offset);

  const result = await db
    .prepare(query)
    .bind(...params)
    .all();

  return result.results.map((row) => ({
    id: row.id as string,
    timestamp: row.timestamp as string,
    requestId: row.request_id as string,
    action: row.action as AuditAction,
    issuer: row.issuer as string,
    subject: row.subject as string,
    keyId: row.key_id as string,
    success: Boolean(row.success),
    errorCode: row.error_code as ErrorCode | undefined,
    metadata: row.metadata as string | undefined,
  }));
}
