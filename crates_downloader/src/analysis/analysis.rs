use std::collections::HashSet;
use tokio::fs::{create_dir_all, remove_dir_all};
use tracing::info;
use diesel_async::RunQueryDsl;
use futures::future::join_all;

use crate::{
    analysis::audit::run_cargo_audit, config::Config, database::Database, models::Crate, repositories::{
        crates::{get_all_crates, get_crates_by_ids, get_top_download_crates}, 
        dependencies::{get_dependencies_for_crate, get_dependencies_for_crates}, 
        download::download_repo, 
        scan_results::get_crate_ids_needing_analysis
    }
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
}

pub async fn analyze_crates(database: &Database, config: &Config) -> Result<(), anyhow::Error> {
    info!("Analyzing crates");
    let all_crates = if config.use_only_first_x_crates > 0 {
        get_top_download_crates(database, config.use_only_first_x_crates as i64).await?
    } else {
        get_all_crates(database).await?
    };
    
    info!("Checking which crates need analyzing...");
    // Batch check which crates need analyzing (single query instead of N queries!)
    let crate_ids_needing_analysis = get_crate_ids_needing_analysis(database, &all_crates).await?;
    
    let crates_to_analyze: Vec<Crate> = all_crates
        .into_iter()
        .filter(|c| crate_ids_needing_analysis.contains(&c.id))
        .collect();
    
    let total_crates = crates_to_analyze.len();
    info!("Found {} crates to analyze", total_crates);

    for (index, c) in crates_to_analyze.iter().enumerate() {
        analyze_crate(c, database).await?;
        
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

/// Analyzes a crate and all its dependencies (bottom-up)
/// Batches inserts for improved performance - analyzes up to 50 crates and inserts all results at once
/// SCALABILITY: Works efficiently even with 10k+ crates and millions of dependencies by:
/// - Using IDs instead of full Crate objects in the stack (memory efficient)
/// - Batch-fetching crates when needed (reduces queries)
/// - Pre-fetching which crates need analysis (eliminates N+1 queries)
/// - Detecting cycles to prevent infinite loops
pub async fn analyze_crate(c: &Crate, database: &Database) -> Result<(), anyhow::Error> {
    // Use ID-based stack for memory efficiency (i64 is 8 bytes vs Crate struct ~100+ bytes)
    let mut stack: Vec<i64> = Vec::new();
    let mut processed: HashSet<i64> = HashSet::new();
    let mut dependencies_queued: HashSet<i64> = HashSet::new();
    let mut pending_results: Vec<AnalysisResult> = Vec::new();
    let mut seen: HashSet<i64> = HashSet::new(); // For cycle detection
    
    // Collect all reachable crate IDs first (BFS to map dependency graph)
    let all_reachable_ids = collect_all_dependency_ids(database, c.id, &mut seen).await?;
    let total_in_tree = all_reachable_ids.len();
    info!("Crate '{}': Found {} total crates in dependency tree (including root)", c.name, total_in_tree);
    
    // Batch-fetch all crates we'll need
    let all_crates_map = get_crates_by_ids(database, &all_reachable_ids).await?;
    
    // Batch-check which ones need analysis (single query!)
    let crates_vec: Vec<Crate> = all_reachable_ids.iter()
        .filter_map(|id| all_crates_map.get(id).cloned())
        .collect();
    let needs_analysis_set = get_crate_ids_needing_analysis(database, &crates_vec).await?;
    let needs_analysis_count = needs_analysis_set.len();
    
    info!("Crate '{}': {} need analysis, {} already up-to-date", 
          c.name, needs_analysis_count, total_in_tree - needs_analysis_count);
    
    // Start with the root crate
    stack.push(c.id);
    
    // Collect crates that can be processed in parallel (same level in dependency tree)
    let mut parallel_batch: Vec<&Crate> = Vec::new();
    const MAX_PARALLEL: usize = 30; // Limit concurrent git clones
    
    while let Some(current_id) = stack.pop() {
        // Skip if already processed
        if processed.contains(&current_id) {
            continue;
        }
        
        // Skip if doesn't need analyzing (using pre-fetched data - no DB query!)
        if !needs_analysis_set.contains(&current_id) {
            processed.insert(current_id);
            continue;
        }
        
        // Get crate from our pre-fetched map
        let current_crate = match all_crates_map.get(&current_id) {
            Some(c) => c,
            None => {
                processed.insert(current_id);
                continue;
            }
        };
        
        // Check if we need to process dependencies first
        if should_process_dependencies_first_optimized(
            current_id,
            &dependencies_queued,
            &processed,
            &needs_analysis_set,
            database,
            &mut stack,
        ).await? {
            dependencies_queued.insert(current_id);
            continue;
        }
        
        // Add to parallel batch instead of processing immediately
        parallel_batch.push(current_crate);
        processed.insert(current_id);
        
        // Process batch when we have enough crates or stack is empty
        if parallel_batch.len() >= MAX_PARALLEL || stack.is_empty() {
            let tasks: Vec<_> = parallel_batch
                .iter()
                .map(|crate_data| async move {
                    analyze_single_crate(crate_data).await
                })
                .collect();
            
            let results = join_all(tasks).await;
            
            // Collect successful results
            for result in results {
                match result {
                    Ok(scan_data) => pending_results.push(scan_data),
                    Err(e) => info!("Failed to analyze crate: {}", e),
                }
            }
            
            parallel_batch.clear();
            
            // Batch insert when we have enough results
            if pending_results.len() >= 50 || stack.is_empty() {
                batch_insert_results(database, &pending_results).await?;
                info!("Batch inserted {} scan results and their audit results", pending_results.len());
                pending_results.clear();
            }
        }
    }
    
    // Insert any remaining results
    if !pending_results.is_empty() {
        batch_insert_results(database, &pending_results).await?;
        info!("Batch inserted final {} scan results and their audit results", pending_results.len());
    }

    Ok(())
}

/// Collects all crate IDs reachable from a starting crate (BFS traversal with batch fetching)
/// Prevents cycles and efficiently maps the entire dependency graph
/// OPTIMIZED: Fetches dependencies in batches to minimize database queries
async fn collect_all_dependency_ids(
    database: &Database,
    start_id: i64,
    seen: &mut HashSet<i64>,
) -> Result<Vec<i64>, anyhow::Error> {
    let mut all_ids: Vec<i64> = Vec::new();
    let mut current_level: Vec<i64> = vec![start_id];
    
    // BFS with batch fetching - process one level at a time
    while !current_level.is_empty() {
        let mut next_level: Vec<i64> = Vec::new();
        
        // Filter to only process unseen crates
        let to_process: Vec<i64> = current_level
            .into_iter()
            .filter(|id| seen.insert(*id))
            .collect();
        
        if to_process.is_empty() {
            break;
        }
        
        all_ids.extend(&to_process);
        
        // Batch-fetch dependencies for ALL crates in this level (single query!)
        let deps_map = get_dependencies_for_crates(database, &to_process).await?;
        
        // Collect all dependencies for next level
        for dep_ids in deps_map.values() {
            for dep_id in dep_ids {
                if !seen.contains(dep_id) {
                    next_level.push(*dep_id);
                }
            }
        }
        
        current_level = next_level;
    }
    
    Ok(all_ids)
}

/// Optimized version: uses IDs instead of full Crate objects and pre-fetched analysis status
/// Determines if dependencies should be processed before the current crate
/// Returns true if dependencies were added to the stack
async fn should_process_dependencies_first_optimized(
    current_id: i64,
    dependencies_queued: &HashSet<i64>,
    processed: &HashSet<i64>,
    needs_analysis_set: &HashSet<i64>,
    database: &Database,
    stack: &mut Vec<i64>,
) -> Result<bool, anyhow::Error> {
    // If we already queued dependencies for this crate, we're ready to process it
    if dependencies_queued.contains(&current_id) {
        return Ok(false);
    }
    
    // Get all dependencies
    let dependencies = get_dependencies_for_crate(database, current_id).await?;
    
    // Find unprocessed dependencies that need analysis
    let unprocessed_dep_ids: Vec<i64> = dependencies
        .iter()
        .map(|d| d.dependency_id)
        .filter(|dep_id| {
            !processed.contains(dep_id) && needs_analysis_set.contains(dep_id)
        })
        .collect();
    
    // If there are unprocessed dependencies, push current crate back and process deps first
    if !unprocessed_dep_ids.is_empty() {
        stack.push(current_id);
        
        // Add dependencies to stack (they'll be processed first due to LIFO)
        for dep_id in unprocessed_dep_ids {
            stack.push(dep_id);
        }
        return Ok(true);
    }
    
    Ok(false)
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
        });
    }
    
    let dir = format!("/tmp/crates/{}", crate_data.name);
    
    // Create parent directory if it doesn't exist
    create_dir_all("/tmp/crates").await?;
    
    
    // Try to download the repository
    match download_repo(&crate_data.repository, &dir).await {
        Ok(_) => {
            // Successfully cloned - perform analysis
            let result_data = perform_analysis(crate_data, &dir).await?;
            
            // Clean up
            if let Err(e) = remove_dir_all(&dir).await {
                info!("Warning: failed to clean up directory {}: {}", dir, e);
            }
            
            info!("Completed analysis for crate: {} (id: {})", crate_data.name, crate_data.id);
            Ok(result_data)
        }
        Err(e) => {
            // Check if it's a private/not found repository error
            if e.to_string().contains("private or not found") {
                info!("Skipping crate {} (id: {}) - repository is private or not found", crate_data.name, crate_data.id);
                // Still create a scan result to mark it as processed
                Ok(AnalysisResult {
                    scan_result: create_placeholder_result(crate_data.id),
                    audit_results: Vec::new(),
                })
            } else {
                // Other errors should be propagated
                Err(e)
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

/// Sample implementation: Run gitleaks to check for secrets
/// Simulates ~3 seconds of processing time
async fn run_gitleaks(_crate_dir: &str, crate_id: i64) -> Result<bool, anyhow::Error> {
    info!("Running gitleaks for crate {}", crate_id);
    
    // Simulate gitleaks execution time
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    
    // TODO: Real implementation would run:
    // Command::new("gitleaks").arg("detect").arg("--source").arg(crate_dir)...
    // Parse results and insert into gitleaks_results table
    
    info!("Completed gitleaks for crate {}", crate_id);
    Ok(false) // No secrets found
}

/// Sample implementation: Compute code similarity with other crates
/// Simulates ~4 seconds of processing time
async fn compute_similarity(_crate_dir: &str, crate_id: i64) -> Result<(), anyhow::Error> {
    info!("Computing code similarity for crate {}", crate_id);
    
    // Simulate similarity computation time
    tokio::time::sleep(tokio::time::Duration::from_secs(4)).await;
    
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
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    
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
    tokio::time::sleep(tokio::time::Duration::from_secs(15)).await;
    
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
        run_gitleaks(crate_dir, crate_id),
        compute_similarity(crate_dir, crate_id),
        check_executable_files(crate_dir, crate_id),
        run_llm_analysis(crate_dir, crate_id),
    );
    
    // Aggregate results from all analyses
    let audit_results = audit_result?;
    
    let cargo_audit_max_dep_score = *audit_results.iter().map(|(_, severity)| severity).max().unwrap_or(&0) as i16;
    let cargo_audit_vulns_count = audit_results.len() as i16;
    let _has_secrets = gitleaks_result?; // TODO: Use this when implementing gitleaks_results table
    similarity_result?; // Just check it succeeded
    let has_executable_files = exec_result?;
    let (llm_malicious_score, llm_notes) = llm_result?;
    
    info!("All parallel analyses completed for crate {}", crate_id);
    
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
    
    let mut conn = database.get_connection().await?;
    
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
    
    diesel::sql_query(&scan_query).execute(&mut conn).await?;
    
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
        diesel::sql_query(&delete_query).execute(&mut conn).await?;
        
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
        
        diesel::sql_query(&audit_query).execute(&mut conn).await?;
    }
    
    Ok(())
}