use crate::schema::{crates, dependencies};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::Deserialize;

// CSV Record structs (for reading from CSV files)
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct CrateRecord {
    pub created_at: String,
    pub description: Option<String>,
    pub documentation: Option<String>,
    pub homepage: Option<String>,
    pub id: i32,
    pub max_features: Option<i32>,
    pub max_upload_size: Option<i64>,
    pub name: String,
    pub readme: Option<String>,
    pub repository: Option<String>,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CrateDownloadRecord {
    pub crate_id: i32,
    pub downloads: i64,
}

#[derive(Debug, Deserialize)]
pub struct DependencyRecord {
    pub crate_id: i32,
    pub version_id: i32,
}

#[derive(Debug, Deserialize)]
pub struct VersionRecord {
    pub id: i32,
    pub crate_id: i32,
}

// Database Insertable structs (for inserting into database)
#[derive(Debug, Insertable)]
#[diesel(table_name = crates)]
pub struct NewCrate {
    pub id: i64,
    pub name: String,
    pub repository: String,
    pub crate_downloads: i64,
    pub crate_created_at: NaiveDateTime,
    pub crate_updated_at: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = dependencies)]
pub struct NewDependency {
    pub crate_id: i64,
    pub dependency_id: i64,
    pub db_created_at: NaiveDateTime,
    pub db_updated_at: NaiveDateTime,
}
