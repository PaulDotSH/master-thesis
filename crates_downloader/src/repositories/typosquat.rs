use crate::database::Database;
use crate::models::{NewTyposquatResult, TyposquatResult};
use crate::schema::typosquat_results;
use anyhow::Result;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use tracing::info;

/// Insert a batch of typosquat results into the database
pub async fn insert_typosquat_results(
    database: &Database,
    results: &[NewTyposquatResult],
) -> Result<usize> {
    if results.is_empty() {
        return Ok(0);
    }

    let mut conn = database.get_connection().await?;

    let inserted = diesel::insert_into(typosquat_results::table)
        .values(results)
        .on_conflict_do_nothing()
        .execute(&mut conn)
        .await?;

    Ok(inserted)
}

/// Get all typosquat results for a specific crate
pub async fn get_typosquats_for_crate(
    database: &Database,
    crate_id: i64,
) -> Result<Vec<TyposquatResult>> {
    let mut conn = database.get_connection().await?;

    let results = typosquat_results::table
        .filter(typosquat_results::crate_id.eq(crate_id))
        .order(typosquat_results::combined_score.desc())
        .load::<TyposquatResult>(&mut conn)
        .await?;

    Ok(results)
}

/// Get all typosquat results with a combined score above a threshold
pub async fn get_high_risk_typosquats(
    database: &Database,
    min_score: i16,
) -> Result<Vec<TyposquatResult>> {
    let mut conn = database.get_connection().await?;

    let results = typosquat_results::table
        .filter(typosquat_results::combined_score.ge(min_score))
        .order(typosquat_results::combined_score.desc())
        .load::<TyposquatResult>(&mut conn)
        .await?;

    Ok(results)
}

/// Count total typosquat results in database
pub async fn count_typosquat_results(database: &Database) -> Result<i64> {
    let mut conn = database.get_connection().await?;

    let count: i64 = typosquat_results::table
        .count()
        .get_result(&mut conn)
        .await?;

    Ok(count)
}

/// Clear all typosquat results (useful for re-running analysis)
pub async fn clear_typosquat_results(database: &Database) -> Result<usize> {
    let mut conn = database.get_connection().await?;

    let deleted = diesel::delete(typosquat_results::table)
        .execute(&mut conn)
        .await?;

    info!("Cleared {} typosquat results", deleted);
    Ok(deleted)
}
