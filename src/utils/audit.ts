import type { AuditAction, AuditLogEntry, ErrorCode } from "~/types";

export async function logAuditEvent(
  db: D1Database,
  entry: Omit<AuditLogEntry, "id" | "timestamp">,
): Promise<void> {
  const id = crypto.randomUUID();
  const timestamp = new Date().toISOString();

  try {
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
    /* istanbul ignore next: logging-only failure path */
  } catch (error) {
    // Log failure but don't crash the request - audit is important but not critical path
    console.error("Failed to write audit log:", {
      entry,
      error: error instanceof Error ? error.message : "Unknown error",
    });
    // Note: In production, this should trigger an alert
  }
}

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
    query += " AND subject LIKE ?";
    // Escape LIKE wildcards to prevent pattern injection
    const escapedSubject = subject.replace(/[%_]/g, "\\$&");
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
