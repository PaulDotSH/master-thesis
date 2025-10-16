use crate::config::Config;
use crate::database::Database;
use crate::models::{Crate, CrateDownloadRecord, CrateRecord, NewCrate};
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

pub async fn get_crate_by_id(db: &Database, crate_id: i64) -> Result<Option<Crate>, anyhow::Error> {
    let mut conn = db.get_connection().await?;
    let result = crates::table
        .find(crate_id)
        .first::<Crate>(&mut conn)
        .await
        .optional()?;
    Ok(result)
}

pub async fn get_all_crates(db: &Database) -> Result<Vec<Crate>, anyhow::Error> {
    let mut conn = db.get_connection().await?;
    let all_crates = crates::table
        .select(Crate::as_select())
        .load::<Crate>(&mut conn)
        .await?;
    Ok(all_crates)
}

pub async fn update_crate(
    db: &Database,
    crate_id: i64,
    name: &str,
    repository: &str,
    downloads: i64,
    crate_created_at: NaiveDateTime,
    crate_updated_at: NaiveDateTime,
) -> Result<(), anyhow::Error> {
    let mut conn = db.get_connection().await?;
    diesel::update(crates::table.find(crate_id))
        .set((
            crates::name.eq(name),
            crates::repository.eq(repository),
            crates::crate_downloads.eq(downloads),
            crates::crate_created_at.eq(crate_created_at),
            crates::crate_updated_at.eq(crate_updated_at),
            crates::db_updated_at.eq(chrono::Utc::now().naive_utc()),
        ))
        .execute(&mut conn)
        .await?;
    Ok(())
}

pub async fn batch_update_crates(
    db: &Database,
    updates: &[(i64, String, String, i64, NaiveDateTime, NaiveDateTime)],
) -> Result<(), anyhow::Error> {
    if updates.is_empty() {
        return Ok(());
    }

    let mut conn = db.get_connection().await?;
    let now = chrono::Utc::now().naive_utc();

    // Helper function to escape single quotes in strings for SQL
    fn escape_sql_string(s: &str) -> String {
        s.replace("'", "''")
    }

    // Build bulk UPDATE using PostgreSQL's UPDATE FROM VALUES
    let values: Vec<String> = updates
        .iter()
        .map(|(id, name, repo, downloads, created, updated)| {
            format!(
                "({}, '{}'::text, '{}'::text, {}, '{}'::timestamp, '{}'::timestamp)",
                id,
                escape_sql_string(name),
                escape_sql_string(repo),
                downloads,
                created.format("%Y-%m-%d %H:%M:%S%.f"),
                updated.format("%Y-%m-%d %H:%M:%S%.f")
            )
        })
        .collect();

    let values_str = values.join(", ");

    let query = format!(
        "UPDATE crates SET 
            name = v.name,
            repository = v.repository,
            crate_downloads = v.downloads,
            crate_created_at = v.created_at,
            crate_updated_at = v.updated_at,
            db_updated_at = '{}'::timestamp
         FROM (VALUES {}) AS v(id, name, repository, downloads, created_at, updated_at)
         WHERE crates.id = v.id",
        now.format("%Y-%m-%d %H:%M:%S%.f"),
        values_str
    );

    diesel::sql_query(&query).execute(&mut conn).await?;
    Ok(())
}
