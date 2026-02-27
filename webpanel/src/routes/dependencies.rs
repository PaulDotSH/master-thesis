use axum::{
    extract::{Query, State},
    Json,
};
use diesel::prelude::*;
use diesel::dsl::count_star;
use diesel_async::RunQueryDsl;
use serde::Deserialize;
use std::sync::Arc;

use crate::db::DbPool;
use crate::models::DependencyWithNames;
use crate::routes::{AppError, PaginatedResponse, PaginationParams, deserialize_option_i64};
use crate::schema::{crates, dependencies};

#[derive(Debug, Deserialize, Default)]
pub struct DependencyFilters {
    #[serde(flatten)]
    pub pagination: PaginationParams,
    #[serde(default, deserialize_with = "deserialize_option_i64")]
    pub crate_id: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_option_i64")]
    pub dependency_id: Option<i64>,
    pub crate_name: Option<String>,
}

pub async fn list_dependencies(
    State(pool): State<Arc<DbPool>>,
    Query(params): Query<DependencyFilters>,
) -> Result<Json<PaginatedResponse<DependencyWithNames>>, AppError> {
    let mut conn = pool.get().await?;

    let page = params.pagination.page.max(1);
    let per_page = params.pagination.per_page.clamp(1, 100);
    let offset = (page - 1) * per_page;

    // Aliases for self-join
    let (crate_c, dep_c) = diesel::alias!(crates as crate_c, crates as dep_c);

    // Build query with joins
    let mut query = dependencies::table
        .inner_join(crate_c.on(crate_c.field(crates::id).eq(dependencies::crate_id)))
        .inner_join(dep_c.on(dep_c.field(crates::id).eq(dependencies::dependency_id)))
        .into_boxed();

    let mut count_query = dependencies::table
        .inner_join(crate_c.on(crate_c.field(crates::id).eq(dependencies::crate_id)))
        .inner_join(dep_c.on(dep_c.field(crates::id).eq(dependencies::dependency_id)))
        .into_boxed();

    // Apply filters
    if let Some(crate_id) = params.crate_id {
        query = query.filter(dependencies::crate_id.eq(crate_id));
        count_query = count_query.filter(dependencies::crate_id.eq(crate_id));
    }
    if let Some(dependency_id) = params.dependency_id {
        query = query.filter(dependencies::dependency_id.eq(dependency_id));
        count_query = count_query.filter(dependencies::dependency_id.eq(dependency_id));
    }
    if let Some(ref crate_name) = params.crate_name {
        let pattern = format!("%{}%", crate_name);
        query = query.filter(crate_c.field(crates::name).ilike(pattern.clone()));
        count_query = count_query.filter(crate_c.field(crates::name).ilike(pattern));
    }

    // Get total count
    let total: i64 = count_query.select(count_star()).first(&mut conn).await?;

    // Apply sorting
    let sort_desc = params.pagination.sort_desc;
    query = match params.pagination.sort_by.as_deref() {
        Some("crate_name") => {
            if sort_desc { query.order(crate_c.field(crates::name).desc()) }
            else { query.order(crate_c.field(crates::name).asc()) }
        }
        Some("dependency_name") => {
            if sort_desc { query.order(dep_c.field(crates::name).desc()) }
            else { query.order(dep_c.field(crates::name).asc()) }
        }
        Some("crate_id") => {
            if sort_desc { query.order(dependencies::crate_id.desc()) }
            else { query.order(dependencies::crate_id.asc()) }
        }
        Some("dependency_id") => {
            if sort_desc { query.order(dependencies::dependency_id.desc()) }
            else { query.order(dependencies::dependency_id.asc()) }
        }
        _ => {
            if sort_desc { query.order(dependencies::crate_id.desc()) }
            else { query.order(dependencies::crate_id.asc()) }
        }
    };

    // Execute query
    let results: Vec<(i64, i64, String, String)> = query
        .select((
            dependencies::crate_id,
            dependencies::dependency_id,
            crate_c.field(crates::name),
            dep_c.field(crates::name),
        ))
        .limit(per_page)
        .offset(offset)
        .load(&mut conn)
        .await?;

    let data: Vec<DependencyWithNames> = results
        .into_iter()
        .map(|(crate_id, dependency_id, crate_name, dependency_name)| {
            DependencyWithNames {
                crate_id,
                crate_name,
                dependency_id,
                dependency_name,
            }
        })
        .collect();

    Ok(Json(PaginatedResponse::new(data, total, page, per_page)))
}
