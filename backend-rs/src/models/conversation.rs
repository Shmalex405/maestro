//! `conversations` and `chat_messages` table rows. Mirrors
//! `backend/app/models/conversation.py` and `chat_message.py`.

use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow)]
pub struct Conversation {
    pub id: String,
    pub title: Option<String>,
    pub assessment_id: Option<String>,
    pub context_summary: Option<String>,
    pub is_archived: Option<bool>,
    pub message_count: Option<i32>,
    pub last_message_preview: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub org_id: Option<String>,
    pub created_by: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct ChatMessage {
    pub id: String,
    pub conversation_id: String,
    pub role: crate::models::sql_enums::MessageRoleDb,
    pub content: String,
    pub tool_calls: Option<JsonValue>,
    pub findings_created: Option<JsonValue>,
    pub created_at: Option<DateTime<Utc>>,
}
