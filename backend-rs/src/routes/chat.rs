//! `/chat` — placeholder implementations mirroring
//! `backend/app/routers/chat.py`.
//!
//! The Python backend currently returns a placeholder string instead of
//! wiring an LLM. We match that text exactly so any client that diffs
//! behavior sees the same output.

use axum::{
    extract::{Query, State},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use futures_core::Stream;
use serde::Deserialize;
use std::{pin::Pin, time::Duration};
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::conversation::{ChatMessage, Conversation};
use crate::schemas::common::{pages_for, PaginatedResponse, PaginationQuery};
use crate::schemas::conversation::{
    ChatMessageCreate, ChatMessageResponse, ChatRequest, ChatResponse,
};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/chat", post(send_message))
        .route("/chat/stream", post(send_message_stream))
        .route("/chat/history", get(get_history).delete(clear_history))
        .route("/chat/message", post(add_message))
}

async fn get_or_create(
    state: &AppState,
    user: &AuthUser,
    conversation_id: Option<&str>,
    assessment_id: Option<&str>,
) -> AppResult<Conversation> {
    if let Some(cid) = conversation_id {
        let mut sql = String::from("SELECT * FROM conversations WHERE id = $1");
        let mut binds: Vec<String> = vec![cid.to_string()];
        if let Some(org) = user.org_id.as_ref() {
            sql.push_str(" AND org_id = $2");
            binds.push(org.clone());
        }
        let mut q = sqlx::query_as::<_, Conversation>(&sql);
        for b in &binds {
            q = q.bind(b);
        }
        let found: Option<Conversation> = q.fetch_optional(&state.pool).await?;
        return found.ok_or_else(|| AppError::NotFound("Conversation not found".into()));
    }
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO conversations (id, assessment_id, org_id, created_by) VALUES ($1, $2, $3, $4)",
    )
    .bind(&id)
    .bind(assessment_id)
    .bind(&user.org_id)
    .bind(&user.id)
    .execute(&state.pool)
    .await?;
    let c: Conversation = sqlx::query_as("SELECT * FROM conversations WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;
    Ok(c)
}

async fn save_message(
    state: &AppState,
    conv: &Conversation,
    role: &str,
    content: &str,
) -> AppResult<ChatMessage> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO chat_messages (id, conversation_id, role, content) VALUES ($1, $2, $3::messagerole, $4)",
    )
    .bind(&id)
    .bind(&conv.id)
    .bind(role)
    .bind(content)
    .execute(&state.pool)
    .await?;

    let preview: Option<String> = Some(content.chars().take(255).collect());
    let title_update = if conv.title.is_none() && role == "user" {
        let t: String = content.chars().take(100).collect();
        Some(if content.chars().count() > 100 {
            format!("{t}...")
        } else {
            t
        })
    } else {
        None
    };

    sqlx::query(
        r#"UPDATE conversations
              SET message_count = COALESCE(message_count, 0) + 1,
                  last_message_preview = $2,
                  title = COALESCE(title, $3),
                  updated_at = NOW()
            WHERE id = $1"#,
    )
    .bind(&conv.id)
    .bind(&preview)
    .bind(&title_update)
    .execute(&state.pool)
    .await?;

    let msg: ChatMessage = sqlx::query_as("SELECT * FROM chat_messages WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;
    Ok(msg)
}

async fn send_message(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ChatRequest>,
) -> AppResult<Json<ChatResponse>> {
    let assessment_id = req.context.as_ref().and_then(|c| c.assessment_id.as_deref());
    let conv = get_or_create(&state, &user, req.conversation_id.as_deref(), assessment_id).await?;
    let user_msg = save_message(&state, &conv, "user", &req.message).await?;
    let head: String = req.message.chars().take(100).collect();
    let placeholder = format!(
        "Message received. This is a placeholder response. Actual LLM integration would process: '{head}...'"
    );
    let assistant_msg = save_message(&state, &conv, "assistant", &placeholder).await?;
    Ok(Json(ChatResponse {
        message: ChatMessageResponse::from(&user_msg),
        conversation_id: conv.id,
        response: ChatMessageResponse::from(&assistant_msg),
    }))
}

async fn send_message_stream(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ChatRequest>,
) -> AppResult<impl IntoResponse> {
    let assessment_id = req.context.as_ref().and_then(|c| c.assessment_id.as_deref());
    let conv = get_or_create(&state, &user, req.conversation_id.as_deref(), assessment_id).await?;
    let _ = save_message(&state, &conv, "user", &req.message).await?;
    let head: String = req.message.chars().take(50).collect();
    let response_text = format!(
        "Processing your message: '{head}...'. This is a streaming placeholder response."
    );

    let state_for_stream = state.clone();
    let conv_id = conv.id.clone();
    let conv_clone = conv.clone();
    let stream: Pin<Box<dyn Stream<Item = Result<Event, std::convert::Infallible>> + Send>> =
        Box::pin(async_stream::stream! {
            yield Ok(Event::default().data(serde_json::json!({
                "type": "conversation_id",
                "content": conv_id,
            }).to_string()));

            let mut full = String::new();
            let words: Vec<&str> = response_text.split(' ').collect();
            for w in words {
                let chunk = format!("{w} ");
                full.push_str(&chunk);
                yield Ok(Event::default().data(serde_json::json!({
                    "type": "text",
                    "content": chunk,
                }).to_string()));
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            let _ = save_message(&state_for_stream, &conv_clone, "assistant", full.trim()).await;
            yield Ok(Event::default().data(serde_json::json!({
                "type": "done",
            }).to_string()));
        });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    conversation_id: String,
    #[serde(flatten)]
    page: PaginationQuery,
}

async fn get_history(
    State(state): State<AppState>,
    Query(q): Query<HistoryQuery>,
    user: AuthUser,
) -> AppResult<Json<PaginatedResponse>> {
    let mut sql = String::from("SELECT * FROM conversations WHERE id = $1");
    let mut binds: Vec<String> = vec![q.conversation_id.clone()];
    if let Some(org) = user.org_id.as_ref() {
        sql.push_str(" AND org_id = $2");
        binds.push(org.clone());
    }
    let mut cq = sqlx::query_as::<_, Conversation>(&sql);
    for b in &binds {
        cq = cq.bind(b);
    }
    let conv: Option<Conversation> = cq.fetch_optional(&state.pool).await?;
    if conv.is_none() {
        return Err(AppError::NotFound("Conversation not found".into()));
    }

    let page = q.page.page.max(1);
    let limit = q.page.limit.clamp(1, 200);
    let offset = (page - 1) * limit;

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM chat_messages WHERE conversation_id = $1")
            .bind(&q.conversation_id)
            .fetch_one(&state.pool)
            .await?;

    let msgs: Vec<ChatMessage> = sqlx::query_as(
        "SELECT * FROM chat_messages WHERE conversation_id = $1 ORDER BY created_at OFFSET $2 LIMIT $3",
    )
    .bind(&q.conversation_id)
    .bind(offset)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    let data: Vec<serde_json::Value> = msgs
        .iter()
        .map(|m| serde_json::to_value(ChatMessageResponse::from(m)).unwrap())
        .collect();

    let pages = pages_for(total, limit);
    Ok(Json(PaginatedResponse {
        data,
        total,
        page,
        limit,
        pages,
        has_more: page < pages,
    }))
}

#[derive(Debug, Deserialize)]
struct ConvIdQuery {
    conversation_id: String,
}

async fn clear_history(
    State(state): State<AppState>,
    Query(q): Query<ConvIdQuery>,
    user: AuthUser,
) -> AppResult<Json<serde_json::Value>> {
    let mut sql = String::from("SELECT id FROM conversations WHERE id = $1");
    let mut binds: Vec<String> = vec![q.conversation_id.clone()];
    if let Some(org) = user.org_id.as_ref() {
        sql.push_str(" AND org_id = $2");
        binds.push(org.clone());
    }
    let mut qx = sqlx::query_scalar::<_, String>(&sql);
    for b in &binds {
        qx = qx.bind(b);
    }
    let exists: Option<String> = qx.fetch_optional(&state.pool).await?;
    if exists.is_none() {
        return Err(AppError::NotFound("Conversation not found".into()));
    }

    let deleted: u64 = sqlx::query("DELETE FROM chat_messages WHERE conversation_id = $1")
        .bind(&q.conversation_id)
        .execute(&state.pool)
        .await?
        .rows_affected();
    sqlx::query("UPDATE conversations SET message_count = 0, last_message_preview = NULL WHERE id = $1")
        .bind(&q.conversation_id)
        .execute(&state.pool)
        .await?;

    Ok(Json(serde_json::json!({
        "status": "ok",
        "deleted_count": deleted,
    })))
}

#[derive(Debug, Deserialize)]
struct AddMessageQuery {
    conversation_id: String,
}

async fn add_message(
    State(state): State<AppState>,
    Query(q): Query<AddMessageQuery>,
    user: AuthUser,
    Json(req): Json<ChatMessageCreate>,
) -> AppResult<Json<ChatMessageResponse>> {
    let mut sql = String::from("SELECT * FROM conversations WHERE id = $1");
    let mut binds: Vec<String> = vec![q.conversation_id.clone()];
    if let Some(org) = user.org_id.as_ref() {
        sql.push_str(" AND org_id = $2");
        binds.push(org.clone());
    }
    let mut qx = sqlx::query_as::<_, Conversation>(&sql);
    for b in &binds {
        qx = qx.bind(b);
    }
    let conv: Option<Conversation> = qx.fetch_optional(&state.pool).await?;
    let conv = conv.ok_or_else(|| AppError::NotFound("Conversation not found".into()))?;

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"INSERT INTO chat_messages
              (id, conversation_id, role, content, tool_calls, findings_created)
           VALUES ($1, $2, $3::messagerole, $4, $5, $6)"#,
    )
    .bind(&id)
    .bind(&conv.id)
    .bind(&req.role)
    .bind(&req.content)
    .bind(&req.tool_calls)
    .bind(&req.findings_created)
    .execute(&state.pool)
    .await?;

    let preview: Option<String> = Some(req.content.chars().take(255).collect());
    sqlx::query(
        r#"UPDATE conversations
              SET message_count = COALESCE(message_count, 0) + 1,
                  last_message_preview = $2,
                  updated_at = NOW()
            WHERE id = $1"#,
    )
    .bind(&conv.id)
    .bind(&preview)
    .execute(&state.pool)
    .await?;

    let msg: ChatMessage = sqlx::query_as("SELECT * FROM chat_messages WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;
    Ok(Json(ChatMessageResponse::from(&msg)))
}
