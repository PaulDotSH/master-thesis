use diesel_async::RunQueryDsl;
use anyhow::Context;
use tokio::fs::{create_dir_all, remove_dir_all};
use tracing::{error, info, warn};

use crate::{
    analysis::{
        audit::run_cargo_audit,
        gitleaks::{run_gitleaks, GitleaksResult},
    },
    config::Config,
    database::Database,
    models::Crate,
    repositories::{
        crates::{get_all_crates, get_top_download_crates},
        download::download_repo,
        scan_results::get_crate_ids_needing_analysis,
    },
};

/// Represents scan result data ready to be inserted into the database
#[derive(Debug, Clone)]
struct ScanResultData {
    crate_id: i64,
    has_malicious_dependencies: bool,
    llm_malicious_score: i16,
    llm_notes: String,
    has_executable_files: bool,
    cargo_audit_max_dep_score: i16,
    cargo_audit_vulns_count: i16,
}

/// Represents complete analysis results including both scan results and audit details
#[derive(Debug, Clone)]
struct AnalysisResult {
    scan_result: ScanResultData,
    audit_results: Vec<(String, u8)>, // (rustsec_id, severity)
    gitleaks_results: Vec<GitleaksResult>,
}

/// OLD: Direct analysis without queue (single-process)
/// This is kept for backwards compatibility but the Redis queue architecture is recommended
#[allow(dead_code)]
pub async fn analyze_crates(database: &Database, config: &Config) -> Result<(), anyhow::Error> {
    info!("Analyzing crates (OLD: direct mode, consider using Redis queue)");
    let all_crates = if config.use_only_first_x_crates > 0 {
        get_top_download_crates(database, config.use_only_first_x_crates as i64)
            .await
            .context("Failed to get top download crates")?
    } else {
        get_all_crates(database)
            .await
            .context("Failed to get all crates")?
    };
    
    info!("Checking which crates need analyzing...");
    // Batch check which crates need analyzing (single query instead of N queries!)
    let crate_ids_needing_analysis = get_crate_ids_needing_analysis(database, &all_crates)
        .await
        .context("Failed to get crate IDs needing analysis")?;
    
    let crates_to_analyze: Vec<Crate> = all_crates
        .into_iter()
        .filter(|c| crate_ids_needing_analysis.contains(&c.id))
        .collect();
    
    let total_crates = crates_to_analyze.len();
    info!("Found {} crates to analyze", total_crates);

    for (index, c) in crates_to_analyze.iter().enumerate() {
        if let Err(e) = analyze_crate(c, database).await {
            error!("Failed to analyze crate '{}' (id: {}): {:?}", c.name, c.id, e);
            // Continue with next crate instead of failing entire analysis
        }
        
        // Print progress every 100 crates
        let processed = index + 1;
        if processed % 100 == 0 || processed == total_crates {
            let remaining = total_crates - processed;
            let percentage = (processed as f64 / total_crates as f64) * 100.0;
            info!("Progress: {}/{} crates analyzed ({:.1}% complete, {} remaining)", 
                  processed, total_crates, percentage, remaining);
        }
    }

    info!("✓ Completed analysis of all {} crates!", total_crates);
    Ok(())
}

/// Analyzes a single crate independently (no dependency traversal)
/// This is designed for distributed worker architecture where each crate is analyzed separately
/// Dependencies will be analyzed by other workers or in separate queue items
pub async fn analyze_crate(c: &Crate, database: &Database) -> Result<(), anyhow::Error> {
    // Check if this crate needs analysis
    let needs_analysis = get_crate_ids_needing_analysis(database, &[c.clone()])
        .await
        .context(format!("Failed to check if crate '{}' needs analysis", c.name))?;
    
    if !needs_analysis.contains(&c.id) {
        info!("Crate '{}' (id: {}) is already up-to-date, skipping", c.name, c.id);
        return Ok(());
    }
    
    info!("Analyzing crate '{}' (id: {})", c.name, c.id);
    
    // Analyze just this crate
    let result = analyze_single_crate(c)
        .await
        .context(format!("Failed to analyze crate '{}'", c.name))?;
    
    // Insert results immediately
    batch_insert_results(database, &[result])
        .await
        .context(format!("Failed to insert results for crate '{}'", c.name))?;
    
    info!("✓ Completed analysis for crate '{}' (id: {})", c.name, c.id);
    Ok(())
}

/// Analyzes a single crate by ID (convenience wrapper for queue workers)
pub async fn analyze_crate_by_id(crate_id: i64, database: &Database) -> Result<(), anyhow::Error> {
    let crate_data = crate::repositories::crates::get_crate_by_id(database, crate_id)
        .await
        .context(format!("Failed to fetch crate with ID {}", crate_id))?;
    
    analyze_crate(&crate_data, database).await
}

/// Analyzes a single crate: downloads, runs analysis tools, and returns results
/// Returns AnalysisResult instead of inserting directly to enable batch inserts
async fn analyze_single_crate(crate_data: &Crate) -> Result<AnalysisResult, anyhow::Error> {
    // Skip crates without a valid repository URL
    if crate_data.repository.is_empty() {
        info!("Skipping crate {} (id: {}) - no repository URL", crate_data.name, crate_data.id);
        // Still create a scan result to mark it as processed
        return Ok(AnalysisResult {
            scan_result: create_placeholder_result(crate_data.id),
            audit_results: Vec::new(),
            gitleaks_results: Vec::new(),
        });
    }
    
    let dir = format!("/tmp/crates/{}", crate_data.name);
    
    // Create parent directory if it doesn't exist
    create_dir_all("/tmp/crates")
        .await
        .context("Failed to create /tmp/crates directory")?;
    
    
    // Try to download the repository
    match download_repo(&crate_data.repository, &dir).await {
        Ok(_) => {
            info!("Successfully downloaded crate '{}' (id: {}) to {}", crate_data.name, crate_data.id, dir);
            
            // Successfully cloned - perform analysis
            let result_data = perform_analysis(crate_data, &dir).await;
            
            // Always clean up, even if analysis failed
            if let Err(e) = remove_dir_all(&dir).await {
                warn!("Failed to clean up directory {}: {:?}", dir, e);
            }
            
            // Now propagate the result
            let result_data = result_data
                .context(format!("Failed to perform analysis for crate '{}'", crate_data.name))?;
            
            info!("Completed analysis for crate: {} (id: {})", crate_data.name, crate_data.id);
            Ok(result_data)
        }
        Err(e) => {
            // Clean up any partial download
            let _ = remove_dir_all(&dir).await;
            
            // Check if it's a private/not found repository error
            if e.to_string().contains("private or not found") {
                info!("Skipping crate {} (id: {}) - repository is private or not found", crate_data.name, crate_data.id);
                // Still create a scan result to mark it as processed
                Ok(AnalysisResult {
                    scan_result: create_placeholder_result(crate_data.id),
                    audit_results: Vec::new(),
                    gitleaks_results: Vec::new(),
                })
            } else {
                // Other errors should be propagated with context
                Err(e).context(format!("Failed to download repository for crate '{}'", crate_data.name))
            }
        }
    }
}

/// Creates a placeholder scan result
fn create_placeholder_result(crate_id: i64) -> ScanResultData {
    ScanResultData {
        crate_id,
        has_malicious_dependencies: false,
        llm_malicious_score: 0,
        llm_notes: "Skipped - no repository or private".to_string(),
        has_executable_files: false,
        cargo_audit_max_dep_score: 0,
        cargo_audit_vulns_count: 0,
    }
}

// Removed - now using the real gitleaks implementation from gitleaks.rs module

/// Sample implementation: Compute code similarity with other crates
/// Simulates ~4 seconds of processing time
async fn compute_similarity(_crate_dir: &str, crate_id: i64) -> Result<(), anyhow::Error> {
    info!("Computing code similarity for crate {}", crate_id);
    
    // Simulate similarity computation time
    // tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;
    
    // TODO: Real implementation would:
    // 1. Extract code features/fingerprints
    // 2. Compare with database of known crates
    // 3. Insert results into code_similarity_results table
    
    info!("Completed similarity analysis for crate {}", crate_id);
    Ok(())
}

/// Sample implementation: Check for executable files
/// Simulates ~1 second of processing time
async fn check_executable_files(_crate_dir: &str, crate_id: i64) -> Result<bool, anyhow::Error> {
    info!("Checking executable files for crate {}", crate_id);
    
    // Simulate file scanning time
    // tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    
    // TODO: Real implementation would:
    // Walk directory tree and check for executable permissions
    // or binary files in suspicious locations
    
    info!("Completed executable file check for crate {}", crate_id);
    Ok(false) // No executable files found
}

/// Sample implementation: Run LLM analysis for malicious code detection
/// Simulates ~15 seconds of processing time (LLM is slow!)
async fn run_llm_analysis(_crate_dir: &str, crate_id: i64) -> Result<(i16, String), anyhow::Error> {
    info!("Running LLM analysis for crate {} (this will take ~15s)...", crate_id);
    
    // Simulate LLM API call time - this is the slowest operation!
    // tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
    
    // TODO: Real implementation would:
    // 1. Read and extract key code snippets
    // 2. Send to LLM API (OpenAI, Claude, etc.)
    // 3. Parse LLM response for malicious patterns
    
    info!("Completed LLM analysis for crate {}", crate_id);
    Ok((0, "LLM: No malicious patterns detected".to_string()))
}

/// Performs all analysis steps in parallel and aggregates results
/// Runs all analysis tools concurrently to maximize throughput
async fn perform_analysis(
    crate_data: &Crate,
    crate_dir: &str,
) -> Result<AnalysisResult, anyhow::Error> {
    let crate_id = crate_data.id;
    
    info!("Starting parallel analysis for crate {} (id: {})", crate_data.name, crate_id);
    
    // Run all analysis steps in parallel using tokio::join!
    // This means all 5 operations happen simultaneously
    let (audit_result, gitleaks_result, similarity_result, exec_result, llm_result) = tokio::join!(
        run_cargo_audit(crate_dir, crate_id),
        run_gitleaks(crate_dir),
        compute_similarity(crate_dir, crate_id),
        check_executable_files(crate_dir, crate_id),
        run_llm_analysis(crate_dir, crate_id),
    );
    
    // Aggregate results from all analyses with proper error context
    let audit_results = audit_result
        .context(format!("cargo audit failed for crate '{}'", crate_data.name))?;
    
    let gitleaks_results = gitleaks_result
        .context(format!("gitleaks failed for crate '{}'", crate_data.name))?;
    
    similarity_result
        .context(format!("similarity analysis failed for crate '{}'", crate_data.name))?;
    
    let has_executable_files = exec_result
        .context(format!("executable file check failed for crate '{}'", crate_data.name))?;
    
    let (llm_malicious_score, llm_notes) = llm_result
        .context(format!("LLM analysis failed for crate '{}'", crate_data.name))?;
    
    let cargo_audit_max_dep_score = *audit_results.iter().map(|(_, severity)| severity).max().unwrap_or(&0) as i16;
    let cargo_audit_vulns_count = audit_results.len() as i16;
    
    info!("All parallel analyses completed for crate '{}' (id: {}): {} vulnerabilities, {} secrets found", 
          crate_data.name, crate_id, cargo_audit_vulns_count, gitleaks_results.len());
    
    Ok(AnalysisResult {
        scan_result: ScanResultData {
            crate_id,
            has_malicious_dependencies: false, // This would be computed from dependency analysis
            llm_malicious_score,
            llm_notes,
            has_executable_files,
            cargo_audit_max_dep_score,
            cargo_audit_vulns_count,
        },
        audit_results,
        gitleaks_results,
    })
}

/// Batch insert scan results and cargo audit results into the database
/// Uses PostgreSQL's INSERT ... ON CONFLICT for efficient upserts
async fn batch_insert_results(
    database: &Database,
    results: &[AnalysisResult],
) -> Result<(), anyhow::Error> {
    if results.is_empty() {
        return Ok(());
    }
    
    let mut conn = database.get_connection()
        .await
        .context("Failed to get database connection for batch insert")?;
    
    // First, insert scan results
    let scan_values: Vec<String> = results
        .iter()
        .map(|r| {
            let s = &r.scan_result;
            format!(
                "({}, {}, {}, '{}', {}, {}, {})",
                s.crate_id,
                s.has_malicious_dependencies,
                s.llm_malicious_score,
                s.llm_notes.replace("'", "''"), // Escape single quotes
                s.has_executable_files,
                s.cargo_audit_max_dep_score,
                s.cargo_audit_vulns_count
            )
        })
        .collect();
    
    let scan_values_str = scan_values.join(", ");
    
    let scan_query = format!(
        "INSERT INTO scan_results (id, has_malicious_dependencies, llm_malicious_score, llm_notes, has_executable_files, cargo_audit_max_dep_score, cargo_audit_vulns_count)
         VALUES {}
         ON CONFLICT (id) DO UPDATE SET
            has_malicious_dependencies = EXCLUDED.has_malicious_dependencies,
            llm_malicious_score = EXCLUDED.llm_malicious_score,
            llm_notes = EXCLUDED.llm_notes,
            has_executable_files = EXCLUDED.has_executable_files,
            cargo_audit_max_dep_score = EXCLUDED.cargo_audit_max_dep_score,
            cargo_audit_vulns_count = EXCLUDED.cargo_audit_vulns_count",
        scan_values_str
    );
    
    diesel::sql_query(&scan_query)
        .execute(&mut conn)
        .await
        .context("Failed to insert scan results")?;
    
    // Second, collect and insert all cargo audit results
    let mut all_audit_results = Vec::new();
    for result in results {
        for (rustsec_id, severity) in &result.audit_results {
            all_audit_results.push((result.scan_result.crate_id, rustsec_id.clone(), *severity));
        }
    }
    
    if !all_audit_results.is_empty() {
        // Clear old audit results for these crates first
        let crate_ids: Vec<String> = results
            .iter()
            .map(|r| r.scan_result.crate_id.to_string())
            .collect();
        let crate_ids_str = crate_ids.join(", ");
        
        let delete_query = format!(
            "DELETE FROM cargo_audit_results WHERE crate IN ({})",
            crate_ids_str
        );
        diesel::sql_query(&delete_query)
            .execute(&mut conn)
            .await
            .context("Failed to delete old cargo audit results")?;
        
        // Insert new audit results
        let audit_values: Vec<String> = all_audit_results
            .iter()
            .map(|(crate_id, rustsec_id, severity)| {
                format!(
                    "({}, '{}', {})",
                    crate_id,
                    rustsec_id.replace("'", "''"),
                    severity
                )
            })
            .collect();
        
        let audit_values_str = audit_values.join(", ");
        
        let audit_query = format!(
            "INSERT INTO cargo_audit_results (crate, rustsec_id, severity)
             VALUES {}",
            audit_values_str
        );
        
        diesel::sql_query(&audit_query)
            .execute(&mut conn)
            .await
            .context("Failed to insert cargo audit results")?;
    }
    
    // Third, collect and insert all gitleaks results
    let mut all_gitleaks_results = Vec::new();
    for result in results {
        for gitleaks_result in &result.gitleaks_results {
            all_gitleaks_results.push((
                result.scan_result.crate_id,
                gitleaks_result.rule_id.clone(),
                gitleaks_result.secret.clone(),
                gitleaks_result.path.clone(),
                gitleaks_result.entropy,
            ));
        }
    }
    
    if !all_gitleaks_results.is_empty() {
        // Clear old gitleaks results for these crates first
        let crate_ids: Vec<String> = results
            .iter()
            .map(|r| r.scan_result.crate_id.to_string())
            .collect();
        let crate_ids_str = crate_ids.join(", ");
        
        let delete_query = format!(
            "DELETE FROM gitleaks_results WHERE crate IN ({})",
            crate_ids_str
        );
        diesel::sql_query(&delete_query)
            .execute(&mut conn)
            .await
            .context("Failed to delete old gitleaks results")?;
        
        // Insert new gitleaks results
        let gitleaks_values: Vec<String> = all_gitleaks_results
            .iter()
            .map(|(crate_id, rule_id, secret, loc, entropy)| {
                format!(
                    "({}, '{}', '{}', '{}', {})",
                    crate_id,
                    rule_id.replace("'", "''"),
                    secret.replace("'", "''"),
                    loc.replace("'", "''"),
                    entropy
                )
            })
            .collect();
        
        let gitleaks_values_str = gitleaks_values.join(", ");
        
        let gitleaks_query = format!(
            "INSERT INTO gitleaks_results (crate, rule_id, secret, loc, entropy)
             VALUES {}",
            gitleaks_values_str
        );
        
        diesel::sql_query(&gitleaks_query)
            .execute(&mut conn)
            .await
            .context("Failed to insert gitleaks results")?;
    }
    
    Ok(())
}