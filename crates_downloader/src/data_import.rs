use crate::config::Config;
use crate::csv_reader::{
    read_crates_csv, read_crates_downloads_csv, read_dependencies_csv, read_versions_csv,
};
use crate::database::Database;
use crate::repositories::{crates as crates_repo, dependencies as deps_repo};
use std::collections::HashMap;

pub async fn populate_db(db: &Database, config: &Config) -> Result<(), anyhow::Error> {
    // Read and insert crates
    let crate_records = read_crates_csv("db-dump/crates.csv")?;
    println!("Number of crates to be inserted: {}", crate_records.len());

    crates_repo::insert_crates(db, &crate_records, config).await?;

    let count = crates_repo::count_crates(db).await?;
    println!("Total crates in database: {}", count);

    // Insert crate downloads
    println!("Inserting crates_downloads...");
    let crates_downloads = read_crates_downloads_csv("db-dump/crate_downloads.csv")?;
    crates_repo::insert_crates_downloads(db, &crates_downloads, config).await?;

    // Read versions and create mapping
    println!("Reading versions.csv to create version->crate mapping...");
    let versions = read_versions_csv("db-dump/versions.csv")?;
    let version_to_crate: HashMap<i32, i32> =
        versions.into_iter().map(|v| (v.id, v.crate_id)).collect();
    println!("Created mapping for {} versions", version_to_crate.len());

    // Build set of existing crate IDs
    println!("Building set of existing crate IDs...");
    let existing_crate_ids: std::collections::HashSet<i32> =
        crate_records.iter().map(|c| c.id).collect();
    println!("Found {} crate IDs in crates.csv", existing_crate_ids.len());

    // Insert dependencies
    println!("Inserting dependencies...");
    let dependencies = read_dependencies_csv("db-dump/dependencies.csv")?;
    println!("Total dependencies to insert: {}", dependencies.len());

    // Disable constraints and triggers for faster insertion
    // This is safe because we are only inserting dependencies that already exist in the database, checked with existing_crate_ids
    deps_repo::disable_dependency_triggers(db).await?;

    deps_repo::insert_dependencies(
        db,
        &dependencies,
        &version_to_crate,
        &existing_crate_ids,
        config,
    )
    .await?;

    deps_repo::enable_dependency_triggers(db).await?;

    println!("Database populated successfully");

    Ok(())
}
