use axum::{
    extract::{Query, State},
    Json,
};
use chrono::NaiveDateTime;
use diesel::dsl::count_star;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::db::DbPool;
use crate::routes::{AppError, PaginatedResponse, PaginationParams, deserialize_option_i64};
use crate::schema::{analysis_metrics, crates};

#[derive(Debug, Deserialize, Default)]
pub struct MetricFilters {
    #[serde(flatten)]
    pub pagination: PaginationParams,
    #[serde(default, deserialize_with = "deserialize_option_i64")]
    pub crate_id: Option<i64>,
    pub crate_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct MetricWithCrate {
    pub id: Uuid,
    pub crate_id: i64,
    pub crate_name: String,
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

pub async fn list_metrics(
    State(pool): State<Arc<DbPool>>,
    Query(params): Query<MetricFilters>,
) -> Result<Json<PaginatedResponse<MetricWithCrate>>, AppError> {
    let mut conn = pool.get().await?;

    let page = params.pagination.page.max(1);
    let per_page = params.pagination.per_page.clamp(1, 100);
    let offset = (page - 1) * per_page;

    let mut query = analysis_metrics::table
        .inner_join(crates::table.on(crates::id.eq(analysis_metrics::crate_id)))
        .into_boxed();

    let mut count_query = analysis_metrics::table
        .inner_join(crates::table.on(crates::id.eq(analysis_metrics::crate_id)))
        .into_boxed();

    if let Some(crate_id) = params.crate_id {
        query = query.filter(analysis_metrics::crate_id.eq(crate_id));
        count_query = count_query.filter(analysis_metrics::crate_id.eq(crate_id));
    }

    if let Some(ref crate_name) = params.crate_name {
        let pattern = format!("%{}%", crate_name);
        query = query.filter(crates::name.ilike(pattern.clone()));
        count_query = count_query.filter(crates::name.ilike(pattern));
    }

    let total: i64 = count_query.select(count_star()).first(&mut conn).await?;

    let sort_desc = params.pagination.sort_desc;
    query = match params.pagination.sort_by.as_deref() {
        Some("crate_name") => {
            if sort_desc {
                query.order(crates::name.desc())
            } else {
                query.order(crates::name.asc())
            }
        }
        Some("total_duration_ms") | Some("total_duration") => {
            if sort_desc {
                query.order(analysis_metrics::total_duration_ms.desc())
            } else {
                query.order(analysis_metrics::total_duration_ms.asc())
            }
        }
        Some("completed_at") => {
            if sort_desc {
                query.order(analysis_metrics::completed_at.desc())
            } else {
                query.order(analysis_metrics::completed_at.asc())
            }
        }
        _ => {
            if sort_desc {
                query.order(analysis_metrics::completed_at.desc())
            } else {
                query.order(analysis_metrics::completed_at.asc())
            }
        }
    };

    type ResultTuple = (
        Uuid,
        i64,
        String,
        i64,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<i64>,
        Option<String>,
        NaiveDateTime,
        NaiveDateTime,
    );

    let rows: Vec<ResultTuple> = query
        .select((
            analysis_metrics::id,
            analysis_metrics::crate_id,
            crates::name,
            analysis_metrics::total_duration_ms,
            analysis_metrics::cargo_audit_duration_ms,
            analysis_metrics::gitleaks_duration_ms,
            analysis_metrics::executable_check_duration_ms,
            analysis_metrics::build_rs_analysis_duration_ms,
            analysis_metrics::llm_analysis_duration_ms,
            analysis_metrics::download_duration_ms,
            analysis_metrics::worker_id,
            analysis_metrics::started_at,
            analysis_metrics::completed_at,
        ))
        .limit(per_page)
        .offset(offset)
        .load(&mut conn)
        .await?;

    let data = rows
        .into_iter()
        .map(|r| MetricWithCrate {
            id: r.0,
            crate_id: r.1,
            crate_name: r.2,
            total_duration_ms: r.3,
            cargo_audit_duration_ms: r.4,
            gitleaks_duration_ms: r.5,
            executable_check_duration_ms: r.6,
            build_rs_analysis_duration_ms: r.7,
            llm_analysis_duration_ms: r.8,
            download_duration_ms: r.9,
            worker_id: r.10,
            started_at: r.11,
            completed_at: r.12,
        })
        .collect();

    Ok(Json(PaginatedResponse::new(data, total, page, per_page)))
}
