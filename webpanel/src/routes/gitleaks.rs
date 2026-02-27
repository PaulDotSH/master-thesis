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
use crate::routes::{AppError, PaginatedResponse, PaginationParams, deserialize_option_i64, deserialize_option_f64};
use crate::schema::{crates, gitleaks_results};

#[derive(Debug, Deserialize, Default)]
pub struct GitleaksFilters {
    #[serde(flatten)]
    pub pagination: PaginationParams,
    #[serde(default, deserialize_with = "deserialize_option_i64")]
    pub crate_id: Option<i64>,
    pub rule_id: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_f64")]
    pub min_entropy: Option<f64>,
    pub crate_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GitleaksWithCrate {
    pub id: Uuid,
    pub crate_id: Option<i64>,
    pub crate_name: Option<String>,
    pub rule_id: String,
    pub secret: String,
    pub loc: String,
    pub entropy: f64,
}

pub async fn list_gitleaks(
    State(pool): State<Arc<DbPool>>,
    Query(params): Query<GitleaksFilters>,
) -> Result<Json<PaginatedResponse<GitleaksWithCrate>>, AppError> {
    let mut conn = pool.get().await?;

    let page = params.pagination.page.max(1);
    let per_page = params.pagination.per_page.clamp(1, 100);
    let offset = (page - 1) * per_page;

    // Build query with left join
    let mut query = gitleaks_results::table
        .left_join(crates::table.on(crates::id.nullable().eq(gitleaks_results::crate_)))
        .into_boxed();

    let mut count_query = gitleaks_results::table
        .left_join(crates::table.on(crates::id.nullable().eq(gitleaks_results::crate_)))
        .into_boxed();

    // Apply filters
    if let Some(crate_id) = params.crate_id {
        query = query.filter(gitleaks_results::crate_.eq(crate_id));
        count_query = count_query.filter(gitleaks_results::crate_.eq(crate_id));
    }
    if let Some(ref rule_id) = params.rule_id {
        let pattern = format!("%{}%", rule_id);
        query = query.filter(gitleaks_results::rule_id.ilike(pattern.clone()));
        count_query = count_query.filter(gitleaks_results::rule_id.ilike(pattern));
    }
    if let Some(min_entropy) = params.min_entropy {
        query = query.filter(gitleaks_results::entropy.ge(min_entropy));
        count_query = count_query.filter(gitleaks_results::entropy.ge(min_entropy));
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
        Some("rule_id") => {
            if sort_desc { query.order(gitleaks_results::rule_id.desc()) }
            else { query.order(gitleaks_results::rule_id.asc()) }
        }
        Some("entropy") => {
            if sort_desc { query.order(gitleaks_results::entropy.desc()) }
            else { query.order(gitleaks_results::entropy.asc()) }
        }
        Some("secret") => {
            if sort_desc { query.order(gitleaks_results::secret.desc()) }
            else { query.order(gitleaks_results::secret.asc()) }
        }
        Some("loc") => {
            if sort_desc { query.order(gitleaks_results::loc.desc()) }
            else { query.order(gitleaks_results::loc.asc()) }
        }
        _ => {
            if sort_desc { query.order(gitleaks_results::id.desc()) }
            else { query.order(gitleaks_results::id.asc()) }
        }
    };

    // Execute query
    let results: Vec<(Uuid, Option<i64>, String, String, String, f64, Option<String>)> = query
        .select((
            gitleaks_results::id,
            gitleaks_results::crate_,
            gitleaks_results::rule_id,
            gitleaks_results::secret,
            gitleaks_results::loc,
            gitleaks_results::entropy,
            crates::name.nullable(),
        ))
        .limit(per_page)
        .offset(offset)
        .load(&mut conn)
        .await?;

    let data: Vec<GitleaksWithCrate> = results
        .into_iter()
        .map(|(id, crate_id, rule_id, secret, loc, entropy, crate_name)| {
            GitleaksWithCrate {
                id,
                crate_id,
                crate_name,
                rule_id,
                secret,
                loc,
                entropy,
            }
        })
        .collect();

    Ok(Json(PaginatedResponse::new(data, total, page, per_page)))
}
