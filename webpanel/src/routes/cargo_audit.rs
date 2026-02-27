use axum::{
    extract::{Query, State},
    Json,
};
use diesel::prelude::*;
use diesel::dsl::count_star;
use diesel_async::RunQueryDsl;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::db::DbPool;
use crate::routes::{AppError, PaginatedResponse, PaginationParams, deserialize_option_i64, deserialize_option_i16};
use crate::schema::{cargo_audit_results, crates};

#[derive(Debug, Deserialize, Default)]
pub struct CargoAuditFilters {
    #[serde(flatten)]
    pub pagination: PaginationParams,
    #[serde(default, deserialize_with = "deserialize_option_i64")]
    pub crate_id: Option<i64>,
    pub rustsec_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_i16")]
    pub min_severity: Option<i16>,
    pub crate_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CargoAuditWithCrate {
    pub id: Uuid,
    pub crate_id: Option<i64>,
    pub crate_name: Option<String>,
    pub rustsec_id: String,
    pub severity: Option<i16>,
}

pub async fn list_cargo_audit(
    State(pool): State<Arc<DbPool>>,
    Query(params): Query<CargoAuditFilters>,
) -> Result<Json<PaginatedResponse<CargoAuditWithCrate>>, AppError> {
    let mut conn = pool.get().await?;

    let page = params.pagination.page.max(1);
    let per_page = params.pagination.per_page.clamp(1, 100);
    let offset = (page - 1) * per_page;

    // Build query with left join to get crate names
    let mut query = cargo_audit_results::table
        .left_join(crates::table.on(crates::id.nullable().eq(cargo_audit_results::crate_)))
        .into_boxed();

    let mut count_query = cargo_audit_results::table
        .left_join(crates::table.on(crates::id.nullable().eq(cargo_audit_results::crate_)))
        .into_boxed();

    // Apply filters
    if let Some(crate_id) = params.crate_id {
        query = query.filter(cargo_audit_results::crate_.eq(crate_id));
        count_query = count_query.filter(cargo_audit_results::crate_.eq(crate_id));
    }
    if let Some(ref rustsec_id) = params.rustsec_id {
        let pattern = format!("%{}%", rustsec_id);
        query = query.filter(cargo_audit_results::rustsec_id.ilike(pattern.clone()));
        count_query = count_query.filter(cargo_audit_results::rustsec_id.ilike(pattern));
    }
    if let Some(min_severity) = params.min_severity {
        query = query.filter(cargo_audit_results::severity.ge(min_severity));
        count_query = count_query.filter(cargo_audit_results::severity.ge(min_severity));
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
        Some("rustsec_id") => {
            if sort_desc { query.order(cargo_audit_results::rustsec_id.desc()) }
            else { query.order(cargo_audit_results::rustsec_id.asc()) }
        }
        Some("severity") => {
            if sort_desc { query.order(cargo_audit_results::severity.desc()) }
            else { query.order(cargo_audit_results::severity.asc()) }
        }
        Some("crate_id") => {
            if sort_desc { query.order(cargo_audit_results::crate_.desc()) }
            else { query.order(cargo_audit_results::crate_.asc()) }
        }
        _ => {
            if sort_desc { query.order(cargo_audit_results::id.desc()) }
            else { query.order(cargo_audit_results::id.asc()) }
        }
    };

    // Execute query
    let results: Vec<(Uuid, Option<i64>, String, Option<i16>, Option<String>)> = query
        .select((
            cargo_audit_results::id,
            cargo_audit_results::crate_,
            cargo_audit_results::rustsec_id,
            cargo_audit_results::severity,
            crates::name.nullable(),
        ))
        .limit(per_page)
        .offset(offset)
        .load(&mut conn)
        .await?;

    let data: Vec<CargoAuditWithCrate> = results
        .into_iter()
        .map(|(id, crate_id, rustsec_id, severity, crate_name)| {
            CargoAuditWithCrate {
                id,
                crate_id,
                crate_name,
                rustsec_id,
                severity,
            }
        })
        .collect();

    Ok(Json(PaginatedResponse::new(data, total, page, per_page)))
}
