use diesel::prelude::*;
use diesel_async::RunQueryDsl;
use crate::database::Database;
use crate::schema::scan_results;
use crate::models::Crate;
use std::collections::HashSet;

/// Batch check which crates need analyzing.
/// Returns a HashSet of crate IDs that need analysis.
pub async fn get_crate_ids_needing_analysis(database: &Database, all_crates: &[Crate]) -> Result<HashSet<i64>, anyhow::Error> {
    let mut conn = database.get_connection().await?;
    
    // Get all scan results for the provided crates in one query
    let crate_ids: Vec<i64> = all_crates.iter().map(|c| c.id).collect();
    
    let scan_results_data: Vec<(i64, chrono::NaiveDateTime)> = scan_results::table
        .filter(scan_results::id.eq_any(&crate_ids))
        .select((scan_results::id, scan_results::db_created_at))
        .load(&mut conn)
        .await?;
    
    // crate_id -> scan_created_at
    let scan_map: std::collections::HashMap<i64, chrono::NaiveDateTime> = 
        scan_results_data.into_iter().collect();
    
    let mut needs_analysis = HashSet::new();
    for crate_data in all_crates {
        match scan_map.get(&crate_data.id) {
            // No scan results exist - needs analyzing
            None => {
                needs_analysis.insert(crate_data.id);
            },
            // check if they're older than the crate update
            Some(&scan_created_at) => {
                if scan_created_at < crate_data.crate_updated_at {
                    needs_analysis.insert(crate_data.id);
                }
            }
        }
    }
    
    Ok(needs_analysis)
}

