//! Shared schema types used across routers.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value as JsonValue;

/// Generic paginated response envelope.
///
/// `hasMore` (serde-renamed from `has_more`) lets the desktop's pagination
/// UI disable the Next button on the last page without doing math itself.
/// Before this field landed, the frontend's `PaginatedResult` type
/// declared `hasMore: boolean` but the backend never sent it, so
/// `!findings.hasMore` was always truthy and Next stayed disabled forever
/// (Findings page on v1.0.15).
#[derive(Debug, Serialize)]
pub struct PaginatedResponse {
    pub data: Vec<JsonValue>,
    pub total: i64,
    pub page: i64,
    pub limit: i64,
    pub pages: i64,
    #[serde(rename = "hasMore")]
    pub has_more: bool,
}

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    #[serde(default = "default_page", deserialize_with = "de_i64_from_str_or_int")]
    pub page: i64,
    #[serde(default = "default_limit", deserialize_with = "de_i64_from_str_or_int")]
    pub limit: i64,
}

fn default_page() -> i64 {
    1
}
fn default_limit() -> i64 {
    20
}

/// axum's `Query` extractor hands every URL-encoded value to serde as a
/// string, but Rust handler structs declare numeric fields as `i64`. The
/// default i64 deserializer rejects strings → "expected i64" 400. This
/// helper parses strings *or* JSON-typed integers, so the same type works
/// for query strings AND embedded JSON bodies. Apply with
/// `#[serde(deserialize_with = "de_i64_from_str_or_int")]`.
fn de_i64_from_str_or_int<'de, D>(d: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StrOrInt<'a> {
        Int(i64),
        Str(&'a str),
    }

    match StrOrInt::deserialize(d)? {
        StrOrInt::Int(n) => Ok(n),
        StrOrInt::Str(s) => s.parse().map_err(D::Error::custom),
    }
}

pub fn pages_for(total: i64, limit: i64) -> i64 {
    if total == 0 || limit <= 0 {
        return 0;
    }
    (total + limit - 1) / limit
}
