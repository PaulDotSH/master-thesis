use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::Serialize;
use uuid::Uuid;

use crate::schema::{
    analysis_metrics, cargo_audit_results, crates, dependencies, gitleaks_results,
    runner_metadata, scan_results, typosquat_results,
};

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

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = dependencies)]
pub struct Dependency {
    pub crate_id: i64,
    pub dependency_id: i64,
    pub db_created_at: NaiveDateTime,
    pub db_updated_at: NaiveDateTime,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = scan_results)]
pub struct ScanResult {
    pub id: i64,
    pub has_malicious_dependencies: bool,
    pub llm_malicious_score: i16,
    pub llm_notes: String,
    pub has_executable_files: bool,
    pub cargo_audit_max_dep_score: i16,
    pub cargo_audit_vulns_count: i16,
    pub db_created_at: NaiveDateTime,
    pub build_rs_network_calls: bool,
    pub build_rs_has_link_directive: bool,
    pub build_rs_entropy_score: f32,
    pub build_rs_has_process_spawning: bool,
    pub build_rs_has_raw_ip: bool,
    pub build_rs_has_free_tlds: bool,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = analysis_metrics)]
pub struct AnalysisMetric {
    pub id: Uuid,
    pub crate_id: i64,
    pub total_duration_ms: i64,
    pub cargo_audit_duration_ms: Option<i64>,
    pub gitleaks_duration_ms: Option<i64>,
    pub executable_check_duration_ms: Option<i64>,
    pub build_rs_analysis_duration_ms: Option<i64>,
    pub llm_analysis_duration_ms: Option<i64>,
    pub download_duration_ms: Option<i64>,
    pub worker_id: Option<String>,
    pub started_at: NaiveDateTime,
    pub completed_at: NaiveDateTime,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = cargo_audit_results)]
pub struct CargoAuditResult {
    pub id: Uuid,
    #[diesel(column_name = crate_)]
    pub crate_id: Option<i64>,
    pub rustsec_id: String,
    pub severity: Option<i16>,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = gitleaks_results)]
pub struct GitleaksResult {
    pub id: Uuid,
    #[diesel(column_name = crate_)]
    pub crate_id: Option<i64>,
    pub rule_id: String,
    pub secret: String,
    pub loc: String,
    pub entropy: f64,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = typosquat_results)]
pub struct TyposquatResult {
    pub id: i64,
    pub crate_id: i64,
    pub similar_crate_id: i64,
    pub levenshtein_score: i16,
    pub damerau_levenshtein_score: i16,
    pub jaro_winkler_score: i16,
    pub keyboard_distance_score: i16,
    pub prefix_similarity_score: i16,
    pub combined_score: i16,
    pub db_created_at: NaiveDateTime,
}

#[derive(Debug, Clone, Queryable, Selectable, Serialize)]
#[diesel(table_name = runner_metadata)]
pub struct RunnerMetadata {
    pub run_time: NaiveDateTime,
    pub last_checked_crate: Option<i64>,
}

// Join models for enriched data

#[derive(Debug, Clone, Serialize)]
pub struct CrateWithScanResult {
    pub id: i64,
    pub name: String,
    pub repository: String,
    pub crate_downloads: i64,
    pub crate_created_at: NaiveDateTime,
    pub crate_updated_at: NaiveDateTime,
    pub scan_result: Option<ScanResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DependencyWithNames {
    pub crate_id: i64,
    pub crate_name: String,
    pub dependency_id: i64,
    pub dependency_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CargoAuditWithCrate {
    pub id: Uuid,
    pub crate_id: Option<i64>,
    pub crate_name: Option<String>,
    pub rustsec_id: String,
    pub severity: Option<i16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GitleaksWithCrate {
    pub id: Uuid,
    pub crate_id: Option<i64>,
    pub crate_name: Option<String>,
    pub rule_id: String,
    pub secret: String,
    pub loc: String,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TyposquatWithNames {
    pub id: i64,
    pub crate_id: i64,
    pub crate_name: String,
    pub similar_crate_id: i64,
    pub similar_crate_name: String,
    pub levenshtein_score: i16,
    pub damerau_levenshtein_score: i16,
    pub jaro_winkler_score: i16,
    pub keyboard_distance_score: i16,
    pub prefix_similarity_score: i16,
    pub combined_score: i16,
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

#[derive(Debug, Clone, Serialize)]
pub struct SeverityDistribution {
    pub severity: Option<i16>,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RiskScoreDistribution {
    pub score_range: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimeSeriesPoint {
    pub date: String,
    pub count: i64,
}
