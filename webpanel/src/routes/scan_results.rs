use axum::{
    extract::{Path, Query, State},
    Json,
};
use diesel::prelude::*;
use diesel::dsl::count_star;
use diesel_async::RunQueryDsl;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::db::DbPool;
use crate::routes::{AppError, PaginatedResponse, PaginationParams, deserialize_option_i16, deserialize_option_bool};
use crate::schema::{crates, scan_results};

#[derive(Debug, Deserialize, Default)]
pub struct ScanResultFilters {
    #[serde(flatten)]
    pub pagination: PaginationParams,
    #[serde(default, deserialize_with = "deserialize_option_bool")]
    pub has_malicious_dependencies: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_option_i16")]
    pub min_llm_score: Option<i16>,
    #[serde(default, deserialize_with = "deserialize_option_i16")]
    pub max_llm_score: Option<i16>,
    #[serde(default, deserialize_with = "deserialize_option_bool")]
    pub has_executable_files: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_option_bool")]
    pub has_vulnerabilities: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_option_bool")]
    pub build_rs_network_calls: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_option_bool")]
    pub build_rs_process_spawning: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_option_bool")]
    pub build_rs_raw_ip: Option<bool>,
    pub crate_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanResultWithCrate {
    pub id: i64,
    pub crate_name: String,
    pub has_malicious_dependencies: bool,
    pub llm_malicious_score: i16,
    pub llm_notes: String,
    pub has_executable_files: bool,
    pub cargo_audit_max_dep_score: i16,
    pub cargo_audit_vulns_count: i16,
    pub build_rs_network_calls: bool,
    pub build_rs_has_link_directive: bool,
    pub build_rs_entropy_score: f32,
    pub build_rs_has_process_spawning: bool,
    pub build_rs_has_raw_ip: bool,
    pub build_rs_has_free_tlds: bool,
}

pub async fn list_scan_results(
    State(pool): State<Arc<DbPool>>,
    Query(params): Query<ScanResultFilters>,
) -> Result<Json<PaginatedResponse<ScanResultWithCrate>>, AppError> {
    let mut conn = pool.get().await?;

    let page = params.pagination.page.max(1);
    let per_page = params.pagination.per_page.clamp(1, 100);
    let offset = (page - 1) * per_page;

    // Build query with join
    let mut query = scan_results::table
        .inner_join(crates::table.on(crates::id.eq(scan_results::id)))
        .into_boxed();

    let mut count_query = scan_results::table
        .inner_join(crates::table.on(crates::id.eq(scan_results::id)))
        .into_boxed();

    // Apply filters
    if let Some(has_malicious) = params.has_malicious_dependencies {
        query = query.filter(scan_results::has_malicious_dependencies.eq(has_malicious));
        count_query = count_query.filter(scan_results::has_malicious_dependencies.eq(has_malicious));
    }
    if let Some(min_score) = params.min_llm_score {
        query = query.filter(scan_results::llm_malicious_score.ge(min_score));
        count_query = count_query.filter(scan_results::llm_malicious_score.ge(min_score));
    }
    if let Some(max_score) = params.max_llm_score {
        query = query.filter(scan_results::llm_malicious_score.le(max_score));
        count_query = count_query.filter(scan_results::llm_malicious_score.le(max_score));
    }
    if let Some(has_exec) = params.has_executable_files {
        query = query.filter(scan_results::has_executable_files.eq(has_exec));
        count_query = count_query.filter(scan_results::has_executable_files.eq(has_exec));
    }
    if let Some(has_vulns) = params.has_vulnerabilities {
        if has_vulns {
            query = query.filter(scan_results::cargo_audit_vulns_count.gt(0i16));
            count_query = count_query.filter(scan_results::cargo_audit_vulns_count.gt(0i16));
        } else {
            query = query.filter(scan_results::cargo_audit_vulns_count.eq(0i16));
            count_query = count_query.filter(scan_results::cargo_audit_vulns_count.eq(0i16));
        }
    }
    if let Some(network) = params.build_rs_network_calls {
        query = query.filter(scan_results::build_rs_network_calls.eq(network));
        count_query = count_query.filter(scan_results::build_rs_network_calls.eq(network));
    }
    if let Some(spawning) = params.build_rs_process_spawning {
        query = query.filter(scan_results::build_rs_has_process_spawning.eq(spawning));
        count_query = count_query.filter(scan_results::build_rs_has_process_spawning.eq(spawning));
    }
    if let Some(raw_ip) = params.build_rs_raw_ip {
        query = query.filter(scan_results::build_rs_has_raw_ip.eq(raw_ip));
        count_query = count_query.filter(scan_results::build_rs_has_raw_ip.eq(raw_ip));
    }
    if let Some(ref crate_name) = params.crate_name {
        let pattern = format!("%{}%", crate_name);
        query = query.filter(crates::name.ilike(pattern.clone()));
        count_query = count_query.filter(crates::name.ilike(pattern));
    }

    // Get total count
    let total: i64 = count_query.select(count_star()).first(&mut conn).await?;

    // Apply sorting
    let sort_desc = params.pagination.sort_desc;
    query = match params.pagination.sort_by.as_deref() {
        Some("crate_name") => {
            if sort_desc { query.order(crates::name.desc()) }
            else { query.order(crates::name.asc()) }
        }
        Some("llm_malicious_score") | Some("llm_score") => {
            if sort_desc { query.order(scan_results::llm_malicious_score.desc()) }
            else { query.order(scan_results::llm_malicious_score.asc()) }
        }
        Some("cargo_audit_vulns_count") | Some("vulns_count") => {
            if sort_desc { query.order(scan_results::cargo_audit_vulns_count.desc()) }
            else { query.order(scan_results::cargo_audit_vulns_count.asc()) }
        }
        Some("has_malicious_dependencies") => {
            if sort_desc { query.order(scan_results::has_malicious_dependencies.desc()) }
            else { query.order(scan_results::has_malicious_dependencies.asc()) }
        }
        Some("build_rs_network_calls") => {
            if sort_desc { query.order(scan_results::build_rs_network_calls.desc()) }
            else { query.order(scan_results::build_rs_network_calls.asc()) }
        }
        Some("build_rs_has_process_spawning") => {
            if sort_desc { query.order(scan_results::build_rs_has_process_spawning.desc()) }
            else { query.order(scan_results::build_rs_has_process_spawning.asc()) }
        }
        _ => {
            if sort_desc { query.order(scan_results::id.desc()) }
            else { query.order(scan_results::id.asc()) }
        }
    };

    // Execute query
    type ResultTuple = (i64, String, bool, i16, String, bool, i16, i16, bool, bool, f32, bool, bool, bool);
    let results: Vec<ResultTuple> = query
        .select((
            scan_results::id,
            crates::name,
            scan_results::has_malicious_dependencies,
            scan_results::llm_malicious_score,
            scan_results::llm_notes,
            scan_results::has_executable_files,
            scan_results::cargo_audit_max_dep_score,
            scan_results::cargo_audit_vulns_count,
            scan_results::build_rs_network_calls,
            scan_results::build_rs_has_link_directive,
            scan_results::build_rs_entropy_score,
            scan_results::build_rs_has_process_spawning,
            scan_results::build_rs_has_raw_ip,
            scan_results::build_rs_has_free_tlds,
        ))
        .limit(per_page)
        .offset(offset)
        .load(&mut conn)
        .await?;

    let data: Vec<ScanResultWithCrate> = results
        .into_iter()
        .map(|r| ScanResultWithCrate {
            id: r.0,
            crate_name: r.1,
            has_malicious_dependencies: r.2,
            llm_malicious_score: r.3,
            llm_notes: r.4,
            has_executable_files: r.5,
            cargo_audit_max_dep_score: r.6,
            cargo_audit_vulns_count: r.7,
            build_rs_network_calls: r.8,
            build_rs_has_link_directive: r.9,
            build_rs_entropy_score: r.10,
            build_rs_has_process_spawning: r.11,
            build_rs_has_raw_ip: r.12,
            build_rs_has_free_tlds: r.13,
        })
        .collect();

    Ok(Json(PaginatedResponse::new(data, total, page, per_page)))
}

pub async fn get_scan_result(
    State(pool): State<Arc<DbPool>>,
    Path(id): Path<i64>,
) -> Result<Json<ScanResultWithCrate>, AppError> {
    let mut conn = pool.get().await?;

    type ResultTuple = (i64, String, bool, i16, String, bool, i16, i16, bool, bool, f32, bool, bool, bool);
    let result: ResultTuple = scan_results::table
        .inner_join(crates::table.on(crates::id.eq(scan_results::id)))
        .filter(scan_results::id.eq(id))
        .select((
            scan_results::id,
            crates::name,
            scan_results::has_malicious_dependencies,
            scan_results::llm_malicious_score,
            scan_results::llm_notes,
            scan_results::has_executable_files,
            scan_results::cargo_audit_max_dep_score,
            scan_results::cargo_audit_vulns_count,
            scan_results::build_rs_network_calls,
            scan_results::build_rs_has_link_directive,
            scan_results::build_rs_entropy_score,
            scan_results::build_rs_has_process_spawning,
            scan_results::build_rs_has_raw_ip,
            scan_results::build_rs_has_free_tlds,
        ))
        .first(&mut conn)
        .await?;

    Ok(Json(ScanResultWithCrate {
        id: result.0,
        crate_name: result.1,
        has_malicious_dependencies: result.2,
        llm_malicious_score: result.3,
        llm_notes: result.4,
        has_executable_files: result.5,
        cargo_audit_max_dep_score: result.6,
        cargo_audit_vulns_count: result.7,
        build_rs_network_calls: result.8,
        build_rs_has_link_directive: result.9,
        build_rs_entropy_score: result.10,
        build_rs_has_process_spawning: result.11,
        build_rs_has_raw_ip: result.12,
        build_rs_has_free_tlds: result.13,
    }))
}
