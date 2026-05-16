use crate::schema::{crates, dependencies, cargo_audit_results, gitleaks_results, typosquat_results};
use chrono::NaiveDateTime;
use diesel::prelude::*;
use serde::Deserialize;

// CSV Record struct
#[derive(Debug, Deserialize, Clone)]
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
    /// Dependency kind: 0=normal, 1=dev, 2=build
    pub kind: i32,
}

#[derive(Debug, Deserialize)]
pub struct VersionRecord {
    pub id: i32,
    pub crate_id: i32,
}

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

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = crates)]
#[allow(dead_code)]
pub struct Crate {
    pub id: i64,
    pub name: String,
    pub repository: String,
    pub crate_downloads: i64,
    pub db_created_at: NaiveDateTime,
    pub db_updated_at: NaiveDateTime,
    pub crate_created_at: NaiveDateTime,
    pub crate_updated_at: NaiveDateTime,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = cargo_audit_results)]
pub struct NewCargoAuditResult {
    pub crate_: Option<i64>,
    pub rustsec_id: String,
    pub severity: Option<i16>,
}

#[derive(Debug, Insertable)]
#[diesel(table_name = gitleaks_results)]
pub struct NewGitleaksResult {
    pub crate_: Option<i64>,
    pub rule_id: String,
    pub secret: String,
    pub loc: String,
    pub entropy: f64,
}

// Typosquat detection models
#[derive(Debug, Clone, Insertable)]
#[diesel(table_name = typosquat_results)]
pub struct NewTyposquatResult {
    pub crate_id: i64,
    pub similar_crate_id: i64,
    pub levenshtein_score: i16,
    pub damerau_levenshtein_score: i16,
    pub jaro_winkler_score: i16,
    pub keyboard_distance_score: i16,
    pub prefix_similarity_score: i16,
    pub combined_score: i16,
}

#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = typosquat_results)]
pub struct TyposquatResult {
    pub id: i64,
    pub crate_id: i64,
    pub similar_crate_id: i64,
    pub levenshtein_score: i16,
    pub damerau_levenshtein_score: i16,
    pub jaro_winkler_score: i16,
    pub keyboard_distance_score: i16,
    pub prefix_similarity_score: i16,
    pub combined_score: i16,
    pub db_created_at: NaiveDateTime,
}
