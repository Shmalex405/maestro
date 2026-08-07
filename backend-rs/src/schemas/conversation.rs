//! Request/response schemas for `/conversations` and `/chat`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::models::conversation::{ChatMessage, Conversation};
use crate::models::sql_enums::WireName;

#[derive(Debug, Deserialize)]
pub struct ConversationCreate {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub assessment_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConversationUpdate {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub context_summary: Option<String>,
    #[serde(default)]
    pub is_archived: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct ConversationResponse {
    pub id: String,
    pub title: Option<String>,
    pub assessment_id: Option<String>,
    pub context_summary: Option<String>,
    pub is_archived: bool,
    pub message_count: i32,
    pub last_message_preview: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
    pub org_id: Option<String>,
    pub created_by: Option<String>,
}

impl From<&Conversation> for ConversationResponse {
    fn from(c: &Conversation) -> Self {
        ConversationResponse {
            id: c.id.clone(),
            title: c.title.clone(),
            assessment_id: c.assessment_id.clone(),
            context_summary: c.context_summary.clone(),
            is_archived: c.is_archived.unwrap_or(false),
            message_count: c.message_count.unwrap_or(0),
            last_message_preview: c.last_message_preview.clone(),
            created_at: c.created_at,
            updated_at: c.updated_at,
            org_id: c.org_id.clone(),
            created_by: c.created_by.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ConversationWithMessagesResponse {
    #[serde(flatten)]
    pub conversation: ConversationResponse,
    pub messages: Vec<ChatMessageResponse>,
}

#[derive(Debug, Deserialize)]
pub struct ChatMessageCreate {
    pub role: String,
    pub content: String,
    #[serde(default)]
    pub tool_calls: Option<JsonValue>,
    #[serde(default)]
    pub findings_created: Option<JsonValue>,
}

#[derive(Debug, Serialize)]
pub struct ChatMessageResponse {
    pub id: String,
    pub conversation_id: String,
    pub role: String,
    pub content: String,
    pub tool_calls: Option<JsonValue>,
    pub findings_created: Option<JsonValue>,
    pub created_at: Option<DateTime<Utc>>,
}

impl From<&ChatMessage> for ChatMessageResponse {
    fn from(m: &ChatMessage) -> Self {
        ChatMessageResponse {
            id: m.id.clone(),
            conversation_id: m.conversation_id.clone(),
            role: m.role.wire_name().to_string(),
            content: m.content.clone(),
            tool_calls: m.tool_calls.clone(),
            findings_created: m.findings_created.clone(),
            created_at: m.created_at,
        }
    }
}

/// Accepted for Pydantic parity — desktop includes these fields today;
/// the chat router is a placeholder so most aren't consumed yet.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ChatContext {
    #[serde(default, rename = "type")]
    pub context_type: Option<String>,
    #[serde(default)]
    pub assessment_id: Option<String>,
    #[serde(default)]
    pub finding_ids: Option<Vec<String>>,
    #[serde(default)]
    pub repo_paths: Option<Vec<String>>,
    #[serde(default)]
    pub scope_summary: Option<String>,
    #[serde(default)]
    pub form_state: Option<JsonValue>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ChatRequest {
    pub message: String,
    #[serde(default)]
    pub conversation_id: Option<String>,
    #[serde(default)]
    pub context: Option<ChatContext>,
    #[serde(default)]
    pub stream: Option<bool>,
    #[serde(default)]
    pub system_prompt: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ChatResponse {
    pub message: ChatMessageResponse,
    pub conversation_id: String,
    pub response: ChatMessageResponse,
}
