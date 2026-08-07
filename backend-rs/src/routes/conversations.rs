//! `/conversations` CRUD + archive/unarchive.
//! Mirror of `backend/app/routers/conversations.py`.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::auth::AuthUser;
use crate::error::{AppError, AppResult};
use crate::models::conversation::{ChatMessage, Conversation};
use crate::schemas::conversation::{
    ChatMessageResponse, ConversationCreate, ConversationResponse, ConversationUpdate,
    ConversationWithMessagesResponse,
};
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/conversations",
            get(list_conversations).post(create_conversation),
        )
        .route(
            "/conversations/:id",
            get(get_conversation)
                .patch(update_conversation)
                .delete(delete_conversation),
        )
        .route("/conversations/:id/archive", post(archive_conversation))
        .route("/conversations/:id/unarchive", post(unarchive_conversation))
}

#[derive(Debug, Deserialize)]
struct ListFilters {
    #[serde(default = "default_limit")]
    limit: i64,
    #[serde(default)]
    include_archived: Option<bool>,
    #[serde(default)]
    assessment_id: Option<String>,
}

fn default_limit() -> i64 {
    50
}

async fn list_conversations(
    State(state): State<AppState>,
    Query(q): Query<ListFilters>,
    user: AuthUser,
) -> AppResult<Json<Vec<ConversationResponse>>> {
    let mut sql = String::from("SELECT * FROM conversations WHERE 1=1");
    let mut args: Vec<String> = Vec::new();

    if let Some(org) = user.org_id.as_ref() {
        args.push(org.clone());
        sql.push_str(&format!(" AND org_id = ${}", args.len()));
    }
    if let Some(a) = q.assessment_id.as_ref() {
        args.push(a.clone());
        sql.push_str(&format!(" AND assessment_id = ${}", args.len()));
    }
    if !q.include_archived.unwrap_or(false) {
        sql.push_str(" AND is_archived = FALSE");
    }
    sql.push_str(" ORDER BY updated_at DESC LIMIT ");
    sql.push_str(&q.limit.clamp(1, 200).to_string());

    let mut qx = sqlx::query_as::<_, Conversation>(&sql);
    for a in &args {
        qx = qx.bind(a);
    }
    let rows = qx.fetch_all(&state.pool).await?;
    Ok(Json(rows.iter().map(ConversationResponse::from).collect()))
}

async fn get_conversation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<ConversationWithMessagesResponse>> {
    let c = fetch_scoped(&state, &id, &user).await?;
    let messages: Vec<ChatMessage> = sqlx::query_as(
        "SELECT * FROM chat_messages WHERE conversation_id = $1 ORDER BY created_at",
    )
    .bind(&c.id)
    .fetch_all(&state.pool)
    .await?;
    Ok(Json(ConversationWithMessagesResponse {
        conversation: ConversationResponse::from(&c),
        messages: messages.iter().map(ChatMessageResponse::from).collect(),
    }))
}

async fn create_conversation(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<ConversationCreate>,
) -> AppResult<(StatusCode, Json<ConversationResponse>)> {
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"INSERT INTO conversations
              (id, title, assessment_id, org_id, created_by)
           VALUES ($1, $2, $3, $4, $5)"#,
    )
    .bind(&id)
    .bind(&req.title)
    .bind(&req.assessment_id)
    .bind(&user.org_id)
    .bind(&user.id)
    .execute(&state.pool)
    .await?;
    let c: Conversation = sqlx::query_as("SELECT * FROM conversations WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.pool)
        .await?;
    Ok((StatusCode::CREATED, Json(ConversationResponse::from(&c))))
}

async fn update_conversation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
    Json(req): Json<ConversationUpdate>,
) -> AppResult<Json<ConversationResponse>> {
    let _ = fetch_scoped(&state, &id, &user).await?;
    let c: Conversation = sqlx::query_as(
        r#"UPDATE conversations
              SET title = COALESCE($2, title),
                  context_summary = COALESCE($3, context_summary),
                  is_archived = COALESCE($4, is_archived),
                  updated_at = NOW()
            WHERE id = $1
            RETURNING *"#,
    )
    .bind(&id)
    .bind(&req.title)
    .bind(&req.context_summary)
    .bind(req.is_archived)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(ConversationResponse::from(&c)))
}

async fn delete_conversation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<StatusCode> {
    let _ = fetch_scoped(&state, &id, &user).await?;
    sqlx::query("DELETE FROM conversations WHERE id = $1")
        .bind(&id)
        .execute(&state.pool)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn archive_conversation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<ConversationResponse>> {
    set_archived(&state, &id, &user, true).await
}

async fn unarchive_conversation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    user: AuthUser,
) -> AppResult<Json<ConversationResponse>> {
    set_archived(&state, &id, &user, false).await
}

async fn set_archived(
    state: &AppState,
    id: &str,
    user: &AuthUser,
    archived: bool,
) -> AppResult<Json<ConversationResponse>> {
    let _ = fetch_scoped(state, id, user).await?;
    let c: Conversation = sqlx::query_as(
        "UPDATE conversations SET is_archived = $2, updated_at = NOW() WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(archived)
    .fetch_one(&state.pool)
    .await?;
    Ok(Json(ConversationResponse::from(&c)))
}

async fn fetch_scoped(state: &AppState, id: &str, user: &AuthUser) -> AppResult<Conversation> {
    let mut sql = String::from("SELECT * FROM conversations WHERE id = $1");
    let mut binds: Vec<String> = vec![id.to_string()];
    if let Some(org) = user.org_id.as_ref() {
        sql.push_str(" AND org_id = $2");
        binds.push(org.clone());
    }
    let mut q = sqlx::query_as::<_, Conversation>(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let row: Option<Conversation> = q.fetch_optional(&state.pool).await?;
    row.ok_or_else(|| AppError::NotFound("Conversation not found".into()))
}
