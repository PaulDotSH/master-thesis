use axum::{extract::State, Json};
use diesel::prelude::*;
use diesel::dsl::count_star;
use diesel::sql_types::{Double, Nullable};
use diesel_async::RunQueryDsl;
use std::sync::Arc;

use crate::db::DbPool;
use crate::models::DashboardStats;
use crate::routes::AppError;
use crate::schema::{analysis_metrics, cargo_audit_results, crates, dependencies, gitleaks_results, scan_results, typosquat_results};

pub async fn get_stats(
    State(pool): State<Arc<DbPool>>,
) -> Result<Json<DashboardStats>, AppError> {
    let mut conn = pool.get().await?;

    // Total crates
    let total_crates: i64 = crates::table
        .select(count_star())
        .first(&mut conn)
        .await?;

    // Total dependencies
    let total_dependencies: i64 = dependencies::table
        .select(count_star())
        .first(&mut conn)
        .await?;

    // Total scanned crates
    let total_scanned: i64 = scan_results::table
        .select(count_star())
        .first(&mut conn)
        .await?;

    // Crates with malicious dependencies
    let malicious_count: i64 = scan_results::table
        .filter(scan_results::has_malicious_dependencies.eq(true))
        .select(count_star())
        .first(&mut conn)
        .await?;

    // High risk crates (LLM score >= 70)
    let high_risk_count: i64 = scan_results::table
        .filter(scan_results::llm_malicious_score.ge(70i16))
        .select(count_star())
        .first(&mut conn)
        .await?;

    // Total vulnerabilities found
    let vulnerabilities_count: i64 = cargo_audit_results::table
        .select(count_star())
        .first(&mut conn)
        .await?;

    // Total secrets found
    let secrets_found: i64 = gitleaks_results::table
        .select(count_star())
        .first(&mut conn)
        .await?;

    // Total typosquat candidates
    let typosquat_count: i64 = typosquat_results::table
        .select(count_star())
        .first(&mut conn)
        .await?;

    // Average analysis duration (ms)
    let avg_analysis_duration_ms: Option<f64> = analysis_metrics::table
        .select(diesel::dsl::sql::<Nullable<Double>>("AVG(total_duration_ms)::float8"))
        .first(&mut conn)
        .await?;

    // Latest analysis duration (ms)
    let latest_analysis_duration_ms: Option<i64> = analysis_metrics::table
        .select(analysis_metrics::total_duration_ms)
        .order(analysis_metrics::completed_at.desc())
        .first::<i64>(&mut conn)
        .await
        .ok();

    Ok(Json(DashboardStats {
        total_crates,
        total_dependencies,
        total_scanned,
        malicious_count,
        high_risk_count,
        vulnerabilities_count,
        secrets_found,
        typosquat_count,
        avg_analysis_duration_ms,
        latest_analysis_duration_ms,
    }))
}

#[derive(serde::Serialize)]
pub struct SeverityCount {
    pub severity: Option<i16>,
    pub count: i64,
}

pub async fn get_severity_distribution(
    State(pool): State<Arc<DbPool>>,
) -> Result<Json<Vec<SeverityCount>>, AppError> {
    let mut conn = pool.get().await?;

    let results: Vec<(Option<i16>, i64)> = cargo_audit_results::table
        .group_by(cargo_audit_results::severity)
        .select((cargo_audit_results::severity, count_star()))
        .load(&mut conn)
        .await?;

    let distribution: Vec<SeverityCount> = results
        .into_iter()
        .map(|(severity, count)| SeverityCount { severity, count })
        .collect();

    Ok(Json(distribution))
}

#[derive(serde::Serialize)]
pub struct RiskScoreCount {
    pub range: String,
    pub count: i64,
}

pub async fn get_risk_distribution(
    State(pool): State<Arc<DbPool>>,
) -> Result<Json<Vec<RiskScoreCount>>, AppError> {
    let mut conn = pool.get().await?;

    // Get all LLM scores and categorize them
    let scores: Vec<i16> = scan_results::table
        .select(scan_results::llm_malicious_score)
        .load(&mut conn)
        .await?;

    let mut low = 0i64;      // 0-30
    let mut medium = 0i64;   // 31-60
    let mut high = 0i64;     // 61-80
    let mut critical = 0i64; // 81-100

    for score in scores {
        match score {
            0..=30 => low += 1,
            31..=60 => medium += 1,
            61..=80 => high += 1,
            _ => critical += 1,
        }
    }

    Ok(Json(vec![
        RiskScoreCount { range: "Low (0-30)".to_string(), count: low },
        RiskScoreCount { range: "Medium (31-60)".to_string(), count: medium },
        RiskScoreCount { range: "High (61-80)".to_string(), count: high },
        RiskScoreCount { range: "Critical (81-100)".to_string(), count: critical },
    ]))
}

#[derive(serde::Serialize)]
pub struct BuildRsStats {
    pub network_calls: i64,
    pub link_directive: i64,
    pub process_spawning: i64,
    pub raw_ip: i64,
    pub free_tlds: i64,
    pub total_scanned: i64,
}

pub async fn get_build_rs_stats(
    State(pool): State<Arc<DbPool>>,
) -> Result<Json<BuildRsStats>, AppError> {
    let mut conn = pool.get().await?;

    let total_scanned: i64 = scan_results::table
        .select(count_star())
        .first(&mut conn)
        .await?;

    let network_calls: i64 = scan_results::table
        .filter(scan_results::build_rs_network_calls.eq(true))
        .select(count_star())
        .first(&mut conn)
        .await?;

    let link_directive: i64 = scan_results::table
        .filter(scan_results::build_rs_has_link_directive.eq(true))
        .select(count_star())
        .first(&mut conn)
        .await?;

    let process_spawning: i64 = scan_results::table
        .filter(scan_results::build_rs_has_process_spawning.eq(true))
        .select(count_star())
        .first(&mut conn)
        .await?;

    let raw_ip: i64 = scan_results::table
        .filter(scan_results::build_rs_has_raw_ip.eq(true))
        .select(count_star())
        .first(&mut conn)
        .await?;

    let free_tlds: i64 = scan_results::table
        .filter(scan_results::build_rs_has_free_tlds.eq(true))
        .select(count_star())
        .first(&mut conn)
        .await?;

    Ok(Json(BuildRsStats {
        network_calls,
        link_directive,
        process_spawning,
        raw_ip,
        free_tlds,
        total_scanned,
    }))
}

#[derive(serde::Serialize)]
pub struct TopDownloadedCrate {
    pub id: i64,
    pub name: String,
    pub downloads: i64,
}

pub async fn get_top_downloaded(
    State(pool): State<Arc<DbPool>>,
) -> Result<Json<Vec<TopDownloadedCrate>>, AppError> {
    let mut conn = pool.get().await?;

    let results: Vec<(i64, String, i64)> = crates::table
        .select((crates::id, crates::name, crates::crate_downloads))
        .order(crates::crate_downloads.desc())
        .limit(10)
        .load(&mut conn)
        .await?;

    let top_crates: Vec<TopDownloadedCrate> = results
        .into_iter()
        .map(|(id, name, downloads)| TopDownloadedCrate { id, name, downloads })
        .collect();

    Ok(Json(top_crates))
}

#[derive(serde::Serialize)]
pub struct RuleIdCount {
    pub rule_id: String,
    pub count: i64,
}

pub async fn get_gitleaks_by_rule(
    State(pool): State<Arc<DbPool>>,
) -> Result<Json<Vec<RuleIdCount>>, AppError> {
    let mut conn = pool.get().await?;

    let results: Vec<(String, i64)> = gitleaks_results::table
        .group_by(gitleaks_results::rule_id)
        .select((gitleaks_results::rule_id, count_star()))
        .order(count_star().desc())
        .limit(10)
        .load(&mut conn)
        .await?;

    let distribution: Vec<RuleIdCount> = results
        .into_iter()
        .map(|(rule_id, count)| RuleIdCount { rule_id, count })
        .collect();

    Ok(Json(distribution))
}
