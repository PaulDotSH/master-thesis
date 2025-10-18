use crate::config::Config;
use crate::database::Database;
use crate::models::{DependencyRecord, NewDependency};
use crate::schema::dependencies;
use chrono::{NaiveDateTime, Utc};
use diesel::prelude::*;
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

#[derive(Debug, Queryable, Selectable)]
#[diesel(table_name = dependencies)]
pub struct Dependency {
    #[allow(dead_code)]
    pub crate_id: i64,
    pub dependency_id: i64,
    #[allow(dead_code)]
    pub db_created_at: NaiveDateTime,
    #[allow(dead_code)]
    pub db_updated_at: NaiveDateTime,
}

pub async fn get_dependencies_for_crate(db: &Database, crate_id: i64) -> Result<Vec<Dependency>, anyhow::Error> {
    let mut conn = db.get_connection().await?;
    let dependencies = dependencies::table
        .filter(dependencies::crate_id.eq(crate_id))
        .select(Dependency::as_select())
        .load(&mut conn)
        .await?;
    Ok(dependencies)
}

/// Batch fetch dependencies for multiple crates at once
/// Returns a HashMap mapping crate_id -> Vec<dependency_id>
pub async fn get_dependencies_for_crates(db: &Database, crate_ids: &[i64]) -> Result<std::collections::HashMap<i64, Vec<i64>>, anyhow::Error> {
    use std::collections::HashMap;
    
    if crate_ids.is_empty() {
        return Ok(HashMap::new());
    }
    
    let mut conn = db.get_connection().await?;
    let dependencies_list: Vec<Dependency> = dependencies::table
        .filter(dependencies::crate_id.eq_any(crate_ids))
        .select(Dependency::as_select())
        .load(&mut conn)
        .await?;
    
    // Group dependencies by crate_id
    let mut deps_map: HashMap<i64, Vec<i64>> = HashMap::new();
    for dep in dependencies_list {
        deps_map.entry(dep.crate_id)
            .or_insert_with(Vec::new)
            .push(dep.dependency_id);
    }
    
    Ok(deps_map)
}

pub async fn bulk_delete_dependencies_for_crates(
    db: &Database,
    crate_ids: &[i64],
) -> Result<(), anyhow::Error> {
    if crate_ids.is_empty() {
        return Ok(());
    }

    let mut conn = db.get_connection().await?;

    diesel::delete(dependencies::table.filter(dependencies::crate_id.eq_any(crate_ids)))
        .execute(&mut conn)
        .await?;

    Ok(())
}

pub async fn insert_dependencies_for_crate(
    db: &Database,
    crate_id: i64,
    dependency_ids: &Vec<i64>,
) -> Result<(), anyhow::Error> {
    if dependency_ids.is_empty() {
        return Ok(());
    }

    // Insert in chunks to avoid "error encoding message to server" for crates with many dependencies
    const CHUNK_SIZE: usize = 1000;
    
    for chunk in dependency_ids.chunks(CHUNK_SIZE) {
        let mut conn = db.get_connection().await?;

        let new_dependencies: Vec<NewDependency> = chunk
            .iter()
            .map(|dep_id| NewDependency {
                crate_id,
                dependency_id: *dep_id,
                db_created_at: Utc::now().naive_utc(),
                db_updated_at: Utc::now().naive_utc(),
            })
            .collect();

        diesel::insert_into(dependencies::table)
            .values(&new_dependencies)
            .on_conflict_do_nothing()
            .execute(&mut conn)
            .await?;
    }

    Ok(())
}
