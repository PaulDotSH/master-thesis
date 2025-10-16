use crate::models::{CrateDownloadRecord, CrateRecord, DependencyRecord, VersionRecord};
use csv::ReaderBuilder;
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

pub fn read_dependencies_csv(file_path: &str) -> Result<Vec<DependencyRecord>, anyhow::Error> {
    let file = File::open(file_path)?;
    let mut rdr = ReaderBuilder::new().has_headers(true).from_reader(file);

    let mut records = Vec::new();

    for result in rdr.deserialize() {
        let record: DependencyRecord = result?;
        records.push(record);
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
