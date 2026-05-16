use crate::models::{CrateDownloadRecord, CrateRecord, DependencyRecord, VersionRecord};
use csv::ReaderBuilder;
use std::collections::{HashMap, HashSet};
use std::fs::File;

pub fn read_crates_csv(file_path: &str) -> Result<Vec<CrateRecord>, anyhow::Error> {
    let file = File::open(file_path)?;
    let mut rdr = ReaderBuilder::new().has_headers(true).from_reader(file);

    let mut records = Vec::new();

    for result in rdr.deserialize() {
        let record: CrateRecord = result?;
        records.push(record);
    }

    Ok(records)
}

pub fn read_crates_downloads_csv(
    file_path: &str,
) -> Result<Vec<CrateDownloadRecord>, anyhow::Error> {
    let file = File::open(file_path)?;
    let mut rdr = ReaderBuilder::new().has_headers(true).from_reader(file);

    let mut records = Vec::new();

    for result in rdr.deserialize() {
        let record: CrateDownloadRecord = result?;
        records.push(record);
    }

    Ok(records)
}

pub fn read_dependencies_csv(file_path: &str, latest_version_ids: &HashSet<i32>) -> Result<Vec<DependencyRecord>, anyhow::Error> {
    let file = File::open(file_path)?;
    let mut rdr = ReaderBuilder::new().has_headers(true).from_reader(file);

    let mut records = Vec::new();

    for result in rdr.deserialize() {
        let record: DependencyRecord = result?;
        // Only include normal runtime dependencies (kind=0) from latest crate version
        if record.kind == 0 && latest_version_ids.contains(&record.version_id) {
            records.push(record);
        }
    }

    Ok(records)
}

pub fn read_versions_csv(file_path: &str) -> Result<Vec<VersionRecord>, anyhow::Error> {
    let file = File::open(file_path)?;
    let mut rdr = ReaderBuilder::new().has_headers(true).from_reader(file);

    let mut records = Vec::new();

    for result in rdr.deserialize() {
        let record: VersionRecord = result?;
        records.push(record);
    }

    Ok(records)
}

/// Uses the highest version_id as the "latest" since version IDs are sequential.
pub fn get_latest_version_ids(versions: &[VersionRecord]) -> HashSet<i32> {
    // Map crate_id -> max version_id
    let mut latest_per_crate: HashMap<i32, i32> = HashMap::new();
    
    for version in versions {
        latest_per_crate
            .entry(version.crate_id)
            .and_modify(|current_max| {
                if version.id > *current_max {
                    *current_max = version.id;
                }
            })
            .or_insert(version.id);
    }
    
    // Convert to HashSet of version IDs
    latest_per_crate.values().copied().collect()
}
