import { getDatabase } from "./log-store";

interface CommandLog {
  tool: string;
  arguments: any;
  target?: string;
  timestamp: string;
  user?: string;
  session_id?: string;
  result_status?: string;
  execution_time_ms?: number;
}

export async function logCommand(log: CommandLog): Promise<void> {
  const db = getDatabase();
  
  const stmt = db.prepare(`
    INSERT INTO audit_logs (timestamp, tool, target, arguments, user, session_id, result_status, execution_time_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  
  stmt.run(
    log.timestamp,
    log.tool,
    log.target || null,
    JSON.stringify(log.arguments),
    log.user || "system",
    log.session_id || null,
    log.result_status || null,
    log.execution_time_ms || null
  );
}

export async function getAuditLogs(options?: {
  tool?: string;
  target?: string;
  since?: string;
  limit?: number;
}): Promise<any[]> {
  const db = getDatabase();
  
  let query = "SELECT * FROM audit_logs WHERE 1=1";
  const params: any[] = [];
  
  if (options?.tool) {
    query += " AND tool = ?";
    params.push(options.tool);
  }
  
  if (options?.target) {
    query += " AND target = ?";
    params.push(options.target);
  }
  
  if (options?.since) {
    query += " AND timestamp >= ?";
    params.push(options.since);
  }
  
  query += " ORDER BY timestamp DESC";
  
  if (options?.limit) {
    query += " LIMIT ?";
    params.push(options.limit);
  }
  
  return db.prepare(query).all(...params);
}
