use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Docker error: {0}")]
    Docker(#[from] bollard::errors::Error),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("HTTP request error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("MCP error: {0}")]
    Mcp(String),

    #[error("LLM error: {0}")]
    Llm(String),

    #[error("Cloud error: {0}")]
    Cloud(String),

    #[error("Authentication error: {0}")]
    Auth(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("Target out of scope: {0}")]
    OutOfScope(String),

    #[error("Container not running")]
    ContainerNotRunning,

    #[error("Operation cancelled")]
    Cancelled,

    #[error("{0}")]
    Other(String),
}

// Implement Serialize for Tauri IPC
impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

// Allow conversion to Tauri command result
impl From<AppError> for tauri::Error {
    fn from(err: AppError) -> Self {
        tauri::Error::Anyhow(err.into())
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
