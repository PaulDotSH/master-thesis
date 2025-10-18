use crate::config::Config;
use crate::csv_reader::{
    read_crates_csv, read_crates_downloads_csv, read_dependencies_csv, read_versions_csv,
};
use crate::database::Database;
use crate::models::CrateDownloadRecord;
use crate::repositories::{crates as crates_repo, dependencies as deps_repo};
use chrono::NaiveDateTime;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

pub async fn populate_db(db: &Database, config: &Config) -> Result<(), anyhow::Error> {
    info!("Starting database population");

    // Read and insert crates
    info!("Reading crates from CSV");
    let crate_records = read_crates_csv("db-dump/crates.csv")?;
    info!("Number of crates to be inserted: {}", crate_records.len());

    info!("Inserting crates into database");
    crates_repo::insert_crates(db, &crate_records, config).await?;

    let count = crates_repo::count_crates(db).await?;
    info!("Total crates in database: {}", count);

    // Insert crate downloads
    info!("Inserting crates_downloads");
    let crates_downloads = read_crates_downloads_csv("db-dump/crate_downloads.csv")?;
    crates_repo::insert_crates_downloads(db, &crates_downloads, config).await?;

    // Read versions and create mapping
    info!("Reading versions.csv to create version->crate mapping");
    let versions = read_versions_csv("db-dump/versions.csv")?;
    let version_to_crate: HashMap<i32, i32> =
        versions.into_iter().map(|v| (v.id, v.crate_id)).collect();
    info!("Created mapping for {} versions", version_to_crate.len());

    // Build set of existing crate IDs
    info!("Building set of existing crate IDs");
    let existing_crate_ids: std::collections::HashSet<i32> =
        crate_records.iter().map(|c| c.id).collect();
    info!("Found {} crate IDs in crates.csv", existing_crate_ids.len());

    // Insert dependencies
    info!("Inserting dependencies");
    let dependencies = read_dependencies_csv("db-dump/dependencies.csv")?;
    info!("Total dependencies to insert: {}", dependencies.len());

    // Disable constraints and triggers for faster insertion
    // This is safe because we are only inserting dependencies that already exist in the database, checked with existing_crate_ids
    debug!("Disabling dependency triggers");
    deps_repo::disable_dependency_triggers(db).await?;

    deps_repo::insert_dependencies(
        db,
        &dependencies,
        &version_to_crate,
        &existing_crate_ids,
        config,
    )
    .await?;

    debug!("Re-enabling dependency triggers");
    deps_repo::enable_dependency_triggers(db).await?;

    info!("Database populated successfully");

    Ok(())
}

pub async fn update_db(db: &Database, config: &Config) -> Result<(), anyhow::Error> {
    info!("Starting optimized database update process");

    info!("Loading all existing crates from database into memory");
    let all_db_crates = crates_repo::get_all_crates(db).await?;
    let db_crates_map: HashMap<i64, crate::models::Crate> =
        all_db_crates.into_iter().map(|c| (c.id, c)).collect();
    info!(
        "Loaded {} crates into memory (~{}MB)",
        db_crates_map.len(),
        (db_crates_map.len() * 200) / 1_000_000 // Rough estimate
    );

    info!("Reading CSV files");
    let crate_records = read_crates_csv("db-dump/crates.csv")?;
    info!("Read {} crates from CSV", crate_records.len());

    let crates_downloads = read_crates_downloads_csv("db-dump/crate_downloads.csv")?;
    let downloads_map: HashMap<i32, i64> = crates_downloads
        .into_iter()
        .map(|d| (d.crate_id, d.downloads))
        .collect();

    info!("Reading versions.csv to create version->crate mapping");
    let versions = read_versions_csv("db-dump/versions.csv")?;
    let version_to_crate: HashMap<i32, i32> =
        versions.into_iter().map(|v| (v.id, v.crate_id)).collect();
    info!("Created mapping for {} versions", version_to_crate.len());

    info!("Reading dependencies from CSV");
    let all_dependencies = read_dependencies_csv("db-dump/dependencies.csv")?;

    // Group dependencies by crate_id (via version_id -> crate_id mapping)
    let mut crate_dependencies: HashMap<i32, Vec<i32>> = HashMap::new();
    for dep in &all_dependencies {
        if let Some(&crate_id) = version_to_crate.get(&dep.version_id) {
            crate_dependencies
                .entry(crate_id)
                .or_insert_with(Vec::new)
                .push(dep.crate_id);
        }
    }

    info!(
        "Grouped dependencies for {} crates",
        crate_dependencies.len()
    );

    // Compare and build batches in memory
    info!("Comparing CSV data with database and building update batches");
    let mut updates_batch = Vec::new();
    let mut inserts_batch = Vec::new();
    let mut crates_to_update_deps: Vec<i64> = Vec::new();
    let mut new_dependencies: Vec<(i64, Vec<i64>)> = Vec::new();
    let mut skipped_count = 0;
    let mut error_count = 0;

    for record in &crate_records {
        let crate_id = record.id as i64;

        // Parse timestamps from CSV
        let csv_updated_at_clean = match record.updated_at.split('+').next() {
            Some(s) => s,
            None => {
                error!(
                    "Failed to parse updated_at timestamp for crate {}: invalid format in '{}'",
                    record.name, record.updated_at
                );
                error_count += 1;
                continue;
            }
        };
        let csv_created_at_clean = match record.created_at.split('+').next() {
            Some(s) => s,
            None => {
                error!(
                    "Failed to parse created_at timestamp for crate {}: invalid format in '{}'",
                    record.name, record.created_at
                );
                error_count += 1;
                continue;
            }
        };

        let csv_updated_at =
            match NaiveDateTime::parse_from_str(csv_updated_at_clean, "%Y-%m-%d %H:%M:%S%.f") {
                Ok(dt) => dt,
                Err(e) => {
                    error!(
                        "Failed to parse updated_at timestamp for crate {}: {} (value: '{}')",
                        record.name, e, csv_updated_at_clean
                    );
                    error_count += 1;
                    continue;
                }
            };
        let csv_created_at =
            match NaiveDateTime::parse_from_str(csv_created_at_clean, "%Y-%m-%d %H:%M:%S%.f") {
                Ok(dt) => dt,
                Err(e) => {
                    error!(
                        "Failed to parse created_at timestamp for crate {}: {} (value: '{}')",
                        record.name, e, csv_created_at_clean
                    );
                    error_count += 1;
                    continue;
                }
            };

        let repository = record
            .repository
            .as_ref()
            .map(|r| r.trim())
            .filter(|r| !r.is_empty())
            .unwrap_or("")
            .to_string();

        let downloads = downloads_map.get(&record.id).copied().unwrap_or(0);

        if let Some(db_crate) = db_crates_map.get(&crate_id) {
            // Crate exists, check if CSV is newer
            if csv_updated_at > db_crate.crate_updated_at {
                updates_batch.push((
                    crate_id,
                    record.name.clone(),
                    repository,
                    downloads,
                    csv_created_at,
                    csv_updated_at,
                ));

                crates_to_update_deps.push(crate_id);

                if let Some(deps) = crate_dependencies.get(&record.id) {
                    let dep_ids: Vec<i64> = deps.iter().map(|&id| id as i64).collect();
                    new_dependencies.push((crate_id, dep_ids));
                }
            } else {
                skipped_count += 1;
            }
        } else {
            // Crate doesn't exist, add to insert batch
            inserts_batch.push((*record).clone());

            if let Some(deps) = crate_dependencies.get(&record.id) {
                let dep_ids: Vec<i64> = deps.iter().map(|&id| id as i64).collect();
                new_dependencies.push((crate_id, dep_ids));
            }
        }
    }

    info!("Analysis complete:");
    info!("  Crates to update: {}", updates_batch.len());
    info!("  Crates to insert: {}", inserts_batch.len());
    info!("  Crates to skip: {}", skipped_count);
    if error_count > 0 {
        warn!(
            "  Parse errors: {} (check error logs for details)",
            error_count
        );
    } else {
        info!("  Parse errors: {}", error_count);
    }

    // Execute batch updates
    if !updates_batch.is_empty() {
        info!("Executing batch updates in chunks of 5000");
        for (i, chunk) in updates_batch.chunks(5000).enumerate() {
            debug!(
                "  Updating chunk {}/{} ({} crates)",
                i + 1,
                (updates_batch.len() + 4999) / 5000,
                chunk.len()
            );
            crates_repo::batch_update_crates(db, chunk).await?;
        }
        info!("Batch updates completed successfully");
    }

    // Insert new crates
    if !inserts_batch.is_empty() {
        info!("Inserting {} new crates", inserts_batch.len());
        crates_repo::insert_crates(db, &inserts_batch, config).await?;

        // Update downloads for new crates
        let downloads_to_insert: Vec<CrateDownloadRecord> = inserts_batch
            .iter()
            .map(|r| CrateDownloadRecord {
                crate_id: r.id,
                downloads: downloads_map.get(&r.id).copied().unwrap_or(0),
            })
            .collect();
        crates_repo::insert_crates_downloads(db, &downloads_to_insert, config).await?;
        info!("New crates inserted successfully");
    }

    // Delete old dependencies for updated crates
    if !crates_to_update_deps.is_empty() {
        info!(
            "Deleting old dependencies for {} crates",
            crates_to_update_deps.len()
        );
        for (i, chunk) in crates_to_update_deps.chunks(10000).enumerate() {
            debug!(
                "  Deleting chunk {}/{}",
                i + 1,
                (crates_to_update_deps.len() + 9999) / 10000
            );
            deps_repo::bulk_delete_dependencies_for_crates(db, chunk).await?;
        }
        info!("Old dependencies deleted successfully");
    }

    // Insert new dependencies
    if !new_dependencies.is_empty() {
        info!(
            "Inserting new dependencies for {} crates",
            new_dependencies.len()
        );
        for (i, (crate_id, dep_ids)) in new_dependencies.iter().enumerate() {
            if i % 1000 == 0 && i > 0 {
                debug!("  Progress: {}/{}", i, new_dependencies.len());
            }
            if !dep_ids.is_empty() {
                deps_repo::insert_dependencies_for_crate(db, *crate_id, dep_ids).await?;
            }
        }
        info!("New dependencies inserted successfully");
    }

    info!("Database update completed:");
    info!("  Updated crates: {}", updates_batch.len());
    info!("  Inserted crates: {}", inserts_batch.len());
    info!("  Skipped (no changes): {}", skipped_count);
    if error_count > 0 {
        warn!("  Parse errors: {}", error_count);
    } else {
        info!("  Parse errors: {}", error_count);
    }

    Ok(())
}
