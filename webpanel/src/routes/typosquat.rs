use axum::{
    extract::{Query, State},
    Json,
};
use diesel::prelude::*;
use diesel::dsl::count_star;
use diesel_async::RunQueryDsl;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::db::DbPool;
use crate::routes::{AppError, PaginatedResponse, PaginationParams, deserialize_option_i64, deserialize_option_i16};
use crate::schema::{crates, typosquat_results};

#[derive(Debug, Deserialize, Default)]
pub struct TyposquatFilters {
    #[serde(flatten)]
    pub pagination: PaginationParams,
    #[serde(default, deserialize_with = "deserialize_option_i64")]
    pub crate_id: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_option_i64")]
    pub similar_crate_id: Option<i64>,
    #[serde(default, deserialize_with = "deserialize_option_i16")]
    pub min_combined_score: Option<i16>,
    pub crate_name: Option<String>,
}

#[derive(Debug, Serialize)]
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

pub async fn list_typosquat(
    State(pool): State<Arc<DbPool>>,
    Query(params): Query<TyposquatFilters>,
) -> Result<Json<PaginatedResponse<TyposquatWithNames>>, AppError> {
    let mut conn = pool.get().await?;

    let page = params.pagination.page.max(1);
    let per_page = params.pagination.per_page.clamp(1, 100);
    let offset = (page - 1) * per_page;

    // Aliases for self-join
    let (crate_c, similar_c) = diesel::alias!(crates as crate_c, crates as similar_c);

    // Build query with joins
    let mut query = typosquat_results::table
        .inner_join(crate_c.on(crate_c.field(crates::id).eq(typosquat_results::crate_id)))
        .inner_join(similar_c.on(similar_c.field(crates::id).eq(typosquat_results::similar_crate_id)))
        .into_boxed();

    let mut count_query = typosquat_results::table
        .inner_join(crate_c.on(crate_c.field(crates::id).eq(typosquat_results::crate_id)))
        .inner_join(similar_c.on(similar_c.field(crates::id).eq(typosquat_results::similar_crate_id)))
        .into_boxed();

    // Apply filters
    if let Some(crate_id) = params.crate_id {
        query = query.filter(typosquat_results::crate_id.eq(crate_id));
        count_query = count_query.filter(typosquat_results::crate_id.eq(crate_id));
    }
    if let Some(similar_crate_id) = params.similar_crate_id {
        query = query.filter(typosquat_results::similar_crate_id.eq(similar_crate_id));
        count_query = count_query.filter(typosquat_results::similar_crate_id.eq(similar_crate_id));
    }
    if let Some(min_score) = params.min_combined_score {
        query = query.filter(typosquat_results::combined_score.ge(min_score));
        count_query = count_query.filter(typosquat_results::combined_score.ge(min_score));
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
        Some("similar_crate_name") => {
            if sort_desc { query.order(similar_c.field(crates::name).desc()) }
            else { query.order(similar_c.field(crates::name).asc()) }
        }
        Some("combined_score") => {
            if sort_desc { query.order(typosquat_results::combined_score.desc()) }
            else { query.order(typosquat_results::combined_score.asc()) }
        }
        Some("levenshtein_score") | Some("levenshtein") => {
            if sort_desc { query.order(typosquat_results::levenshtein_score.desc()) }
            else { query.order(typosquat_results::levenshtein_score.asc()) }
        }
        Some("damerau_levenshtein_score") => {
            if sort_desc { query.order(typosquat_results::damerau_levenshtein_score.desc()) }
            else { query.order(typosquat_results::damerau_levenshtein_score.asc()) }
        }
        Some("jaro_winkler_score") => {
            if sort_desc { query.order(typosquat_results::jaro_winkler_score.desc()) }
            else { query.order(typosquat_results::jaro_winkler_score.asc()) }
        }
        Some("keyboard_distance_score") => {
            if sort_desc { query.order(typosquat_results::keyboard_distance_score.desc()) }
            else { query.order(typosquat_results::keyboard_distance_score.asc()) }
        }
        Some("prefix_similarity_score") => {
            if sort_desc { query.order(typosquat_results::prefix_similarity_score.desc()) }
            else { query.order(typosquat_results::prefix_similarity_score.asc()) }
        }
        _ => {
            if sort_desc { query.order(typosquat_results::id.desc()) }
            else { query.order(typosquat_results::id.asc()) }
        }
    };

    // Execute query
    type ResultTuple = (i64, i64, i64, i16, i16, i16, i16, i16, i16, String, String);
    let results: Vec<ResultTuple> = query
        .select((
            typosquat_results::id,
            typosquat_results::crate_id,
            typosquat_results::similar_crate_id,
            typosquat_results::levenshtein_score,
            typosquat_results::damerau_levenshtein_score,
            typosquat_results::jaro_winkler_score,
            typosquat_results::keyboard_distance_score,
            typosquat_results::prefix_similarity_score,
            typosquat_results::combined_score,
            crate_c.field(crates::name),
            similar_c.field(crates::name),
        ))
        .limit(per_page)
        .offset(offset)
        .load(&mut conn)
        .await?;

    let data: Vec<TyposquatWithNames> = results
        .into_iter()
        .map(|r| TyposquatWithNames {
            id: r.0,
            crate_id: r.1,
            similar_crate_id: r.2,
            levenshtein_score: r.3,
            damerau_levenshtein_score: r.4,
            jaro_winkler_score: r.5,
            keyboard_distance_score: r.6,
            prefix_similarity_score: r.7,
            combined_score: r.8,
            crate_name: r.9,
            similar_crate_name: r.10,
        })
        .collect();

    Ok(Json(PaginatedResponse::new(data, total, page, per_page)))
}
