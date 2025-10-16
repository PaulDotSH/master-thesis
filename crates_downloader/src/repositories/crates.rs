use crate::config::Config;
use crate::database::Database;
use crate::models::{CrateDownloadRecord, CrateRecord, NewCrate};
use crate::schema::crates;
use chrono::NaiveDateTime;
use diesel::prelude::*;
use diesel_async::RunQueryDsl;

pub async fn insert_crates(
    db: &Database,
    crates: &Vec<CrateRecord>,
    config: &Config,
) -> Result<(), anyhow::Error> {
    for chunk in crates.chunks(config.insert_crates_in_chunks) {
        let mut conn = db.get_connection().await?;

        let new_crates: Vec<NewCrate> = chunk
            .iter()
            .filter_map(|record| {
                // Keep all crates, use empty string for missing repository
                let repository = record
                    .repository
                    .as_ref()
                    .map(|r| r.trim())
                    .filter(|r| !r.is_empty())
                    .unwrap_or("")
                    .to_string();

                // Strip timezone from timestamps (format is "2023-05-01 12:06:24.629411+00")
                let created_at_clean = record.created_at.split('+').next()?;
                let updated_at_clean = record.updated_at.split('+').next()?;

                let created_at =
                    NaiveDateTime::parse_from_str(created_at_clean, "%Y-%m-%d %H:%M:%S%.f").ok()?;
                let updated_at =
                    NaiveDateTime::parse_from_str(updated_at_clean, "%Y-%m-%d %H:%M:%S%.f").ok()?;

                Some(NewCrate {
                    id: record.id as i64,
                    name: record.name.clone(),
                    repository,
                    crate_downloads: 0, // Will be updated from crate_downloads.csv
                    crate_created_at: created_at,
                    crate_updated_at: updated_at,
                })
            })
            .collect();

        diesel::insert_into(crates::table)
            .values(&new_crates)
            .on_conflict_do_nothing()
            .execute(&mut conn)
            .await?;
    }

    Ok(())
}

pub async fn insert_crates_downloads(
    db: &Database,
    crates_downloads: &Vec<CrateDownloadRecord>,
    config: &Config,
) -> Result<(), anyhow::Error> {
    for chunk in crates_downloads.chunks(config.insert_crates_in_chunks) {
        let mut conn = db.get_connection().await?;

        // Build bulk UPDATE using PostgreSQL's UPDATE FROM VALUES
        let values: Vec<String> = chunk
            .iter()
            .map(|record| format!("({}, {})", record.crate_id, record.downloads))
            .collect();

        let values_str = values.join(", ");

        let query = format!(
            "UPDATE crates SET crate_downloads = v.downloads 
             FROM (VALUES {}) AS v(id, downloads) 
             WHERE crates.id = v.id",
            values_str
        );

        diesel::sql_query(&query).execute(&mut conn).await?;
    }

    Ok(())
}

pub async fn count_crates(db: &Database) -> Result<i64, anyhow::Error> {
    let mut conn = db.get_connection().await?;
    let count: i64 = crates::table.count().get_result(&mut conn).await?;
    Ok(count)
}
