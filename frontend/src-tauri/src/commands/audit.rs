use crate::database::{AuditLog, Database};
use crate::error::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAuditLogsParams {
    pub limit: Option<i32>,
    pub offset: Option<i32>,
}

#[tauri::command]
pub async fn get_audit_logs(params: Option<GetAuditLogsParams>) -> Result<Vec<AuditLog>> {
    info!("Getting audit logs");

    let db = Database::new()?;
    let params = params.unwrap_or(GetAuditLogsParams {
        limit: None,
        offset: None,
    });

    db.get_audit_logs(params.limit, params.offset)
}
