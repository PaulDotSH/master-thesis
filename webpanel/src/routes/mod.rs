pub mod crates;
pub mod dashboard;
pub mod dependencies;
pub mod scan_results;
pub mod cargo_audit;
pub mod gitleaks;
pub mod metrics;
pub mod typosquat;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::str::FromStr;

// Helper to deserialize numbers from strings (query params are always strings)
fn deserialize_from_str<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: FromStr + Default,
    T::Err: std::fmt::Display,
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) if !s.is_empty() => s.parse().map_err(D::Error::custom),
        _ => Ok(T::default()),
    }
}

fn deserialize_bool_from_str<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s.as_deref() {
        Some("true") | Some("1") => Ok(true),
        _ => Ok(false),
    }
}

// Public helpers for optional numeric/bool fields in filter structs
pub fn deserialize_option_i64<'de, D>(deserializer: D) -> Result<Option<i64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) if !s.is_empty() => s.parse().map(Some).map_err(D::Error::custom),
        _ => Ok(None),
    }
}

pub fn deserialize_option_i16<'de, D>(deserializer: D) -> Result<Option<i16>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) if !s.is_empty() => s.parse().map(Some).map_err(D::Error::custom),
        _ => Ok(None),
    }
}

pub fn deserialize_option_f64<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) if !s.is_empty() => s.parse().map(Some).map_err(D::Error::custom),
        _ => Ok(None),
    }
}

pub fn deserialize_option_bool<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s.as_deref() {
        Some("true") | Some("1") => Ok(Some(true)),
        Some("false") | Some("0") => Ok(Some(false)),
        _ => Ok(None),
    }
}

// Common query parameters for pagination and sorting
#[derive(Debug, Deserialize, Default)]
pub struct PaginationParams {
    #[serde(default = "default_page", deserialize_with = "deserialize_from_str")]
    pub page: i64,
    #[serde(default = "default_per_page", deserialize_with = "deserialize_from_str")]
    pub per_page: i64,
    pub sort_by: Option<String>,
    #[serde(default, deserialize_with = "deserialize_bool_from_str")]
    pub sort_desc: bool,
}

fn default_page() -> i64 { 1 }
fn default_per_page() -> i64 { 50 }

// Paginated response wrapper
#[derive(Debug, Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub total: i64,
    pub page: i64,
    pub per_page: i64,
    pub total_pages: i64,
}

impl<T> PaginatedResponse<T> {
    pub fn new(data: Vec<T>, total: i64, page: i64, per_page: i64) -> Self {
        let total_pages = (total as f64 / per_page as f64).ceil() as i64;
        Self {
            data,
            total,
            page,
            per_page,
            total_pages,
        }
    }
}

// Error handling
pub struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {:?}", self.0);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
