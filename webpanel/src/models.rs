use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::Serialize;
use uuid::Uuid;

use crate::schema::crates;

// Queryable models with Serialize for JSON responses

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = crates)]
pub struct Crate {
    pub id: i64,
    pub name: String,
    pub repository: String,
    pub crate_downloads: i64,
    pub db_created_at: NaiveDateTime,
    pub db_updated_at: NaiveDateTime,
    pub crate_created_at: NaiveDateTime,
    pub crate_updated_at: NaiveDateTime,
}






#[derive(Debug, Clone, Serialize)]
pub struct DependencyWithNames {
    pub crate_id: i64,
    pub crate_name: String,
    pub dependency_id: i64,
    pub dependency_name: String,
}


// Statistics models for dashboard

#[derive(Debug, Clone, Serialize)]
pub struct DashboardStats {
    pub total_crates: i64,
    pub total_dependencies: i64,
    pub total_scanned: i64,
    pub malicious_count: i64,
    pub high_risk_count: i64,
    pub vulnerabilities_count: i64,
    pub secrets_found: i64,
    pub typosquat_count: i64,
    pub avg_analysis_duration_ms: Option<f64>,
    pub latest_analysis_duration_ms: Option<i64>,
}
