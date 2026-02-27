use axum::{
    extract::{Path, Query, State},
    Json,
};
use diesel::prelude::*;
use diesel::dsl::count_star;
use diesel_async::RunQueryDsl;
use serde::Deserialize;
use std::sync::Arc;

use crate::db::DbPool;
use crate::models::Crate;
use crate::routes::{AppError, PaginatedResponse, PaginationParams, deserialize_option_i64};
use crate::schema::crates;

#[derive(Debug, Deserialize, Default)]
pub struct CrateFilters {
    #[serde(flatten)]
    pub pagination: PaginationParams,
    pub search: Option<String>,
    #[serde(default, deserialize_with = "deserialize_option_i64")]
    pub min_downloads: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_option_i64")]
    pub max_downloads: Option<i64>,
}

pub async fn list_crates(
    State(pool): State<Arc<DbPool>>,
    Query(params): Query<CrateFilters>,
) -> Result<Json<PaginatedResponse<Crate>>, AppError> {
    let mut conn = pool.get().await?;
    
    let page = params.pagination.page.max(1);
    let per_page = params.pagination.per_page.clamp(1, 100);
    let offset = (page - 1) * per_page;

    // Build base query for filtering
    let mut query = crates::table.into_boxed();
    let mut count_query = crates::table.into_boxed();

    // Apply search filter
    if let Some(ref search) = params.search {
        let pattern = format!("%{}%", search);
        query = query.filter(crates::name.ilike(pattern.clone()));
        count_query = count_query.filter(crates::name.ilike(pattern));
    }

    // Apply download filters
    if let Some(min) = params.min_downloads {
        query = query.filter(crates::crate_downloads.ge(min));
        count_query = count_query.filter(crates::crate_downloads.ge(min));
    }
    if let Some(max) = params.max_downloads {
        query = query.filter(crates::crate_downloads.le(max));
        count_query = count_query.filter(crates::crate_downloads.le(max));
    }

    // Get total count
    let total: i64 = count_query.select(count_star()).first(&mut conn).await?;

    // Apply sorting
    let sort_desc = params.pagination.sort_desc;
    query = match params.pagination.sort_by.as_deref() {
        Some("name") => {
            if sort_desc { query.order(crates::name.desc()) }
            else { query.order(crates::name.asc()) }
        }
        Some("crate_downloads") | Some("downloads") => {
            if sort_desc { query.order(crates::crate_downloads.desc()) }
            else { query.order(crates::crate_downloads.asc()) }
        }
        Some("crate_created_at") | Some("created_at") => {
            if sort_desc { query.order(crates::crate_created_at.desc()) }
            else { query.order(crates::crate_created_at.asc()) }
        }
        Some("crate_updated_at") | Some("updated_at") => {
            if sort_desc { query.order(crates::crate_updated_at.desc()) }
            else { query.order(crates::crate_updated_at.asc()) }
        }
        Some("repository") => {
            if sort_desc { query.order(crates::repository.desc()) }
            else { query.order(crates::repository.asc()) }
        }
        _ => {
            if sort_desc { query.order(crates::id.desc()) }
            else { query.order(crates::id.asc()) }
        }
    };

    // Execute query with pagination
    let data: Vec<Crate> = query
        .limit(per_page)
        .offset(offset)
        .load(&mut conn)
        .await?;

    Ok(Json(PaginatedResponse::new(data, total, page, per_page)))
}

pub async fn get_crate(
    State(pool): State<Arc<DbPool>>,
    Path(id): Path<i64>,
) -> Result<Json<Crate>, AppError> {
    let mut conn = pool.get().await?;

    let crate_: Crate = crates::table
        .find(id)
        .first(&mut conn)
        .await?;

    Ok(Json(crate_))
}

pub async fn get_crate_by_name(
    State(pool): State<Arc<DbPool>>,
    Path(name): Path<String>,
) -> Result<Json<Crate>, AppError> {
    let mut conn = pool.get().await?;

    let crate_: Crate = crates::table
        .filter(crates::name.eq(&name))
        .first(&mut conn)
        .await?;

    Ok(Json(crate_))
}
