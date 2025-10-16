use crate::config::Config;
use crate::database::Database;
use crate::models::{DependencyRecord, NewDependency};
use crate::schema::dependencies;
use chrono::Utc;
use diesel_async::RunQueryDsl;
use std::collections::{HashMap, HashSet};

pub async fn insert_dependencies(
    db: &Database,
    dependencies: &Vec<DependencyRecord>,
    version_to_crate: &HashMap<i32, i32>,
    existing_crate_ids: &HashSet<i32>,
    config: &Config,
) -> Result<(), anyhow::Error> {
    let mut skipped_missing_version = 0;
    let mut skipped_missing_dependency = 0;
    let mut skipped_missing_owner = 0;

    for chunk in dependencies.chunks(config.insert_crates_in_chunks) {
        let mut conn = db.get_connection().await?;

        let new_dependencies: Vec<NewDependency> = chunk
            .iter()
            .filter_map(|record| {
                // Look up the crate_id from the version_id
                let crate_id = match version_to_crate.get(&record.version_id) {
                    Some(id) => *id,
                    None => {
                        skipped_missing_version += 1;
                        return None;
                    }
                };

                // Check that the owning crate exists
                if !existing_crate_ids.contains(&crate_id) {
                    skipped_missing_owner += 1;
                    return None;
                }

                // Check that the dependency crate exists
                if !existing_crate_ids.contains(&record.crate_id) {
                    skipped_missing_dependency += 1;
                    return None;
                }

                Some(NewDependency {
                    crate_id: crate_id as i64,
                    dependency_id: record.crate_id as i64,
                    db_created_at: Utc::now().naive_utc(),
                    db_updated_at: Utc::now().naive_utc(),
                })
            })
            .collect();

        diesel::insert_into(dependencies::table)
            .values(&new_dependencies)
            .on_conflict_do_nothing()
            .execute(&mut conn)
            .await?;
    }

    if skipped_missing_version > 0 {
        println!(
            "Skipped {} dependencies due to missing version_id",
            skipped_missing_version
        );
    }
    if skipped_missing_owner > 0 {
        println!(
            "Skipped {} dependencies due to missing owner crate",
            skipped_missing_owner
        );
    }
    if skipped_missing_dependency > 0 {
        println!(
            "Skipped {} dependencies due to missing dependency crate",
            skipped_missing_dependency
        );
    }

    Ok(())
}

pub async fn disable_dependency_triggers(db: &Database) -> Result<(), anyhow::Error> {
    let mut conn = db.get_connection().await?;
    diesel::sql_query("ALTER TABLE dependencies DISABLE TRIGGER ALL")
        .execute(&mut conn)
        .await?;
    Ok(())
}

pub async fn enable_dependency_triggers(db: &Database) -> Result<(), anyhow::Error> {
    let mut conn = db.get_connection().await?;
    diesel::sql_query("ALTER TABLE dependencies ENABLE TRIGGER ALL")
        .execute(&mut conn)
        .await?;
    Ok(())
}
