use diesel_async::RunQueryDsl;
use anyhow::Context;
use chrono::Utc;
use std::time::Instant;
use tokio::fs::{create_dir_all, remove_dir_all};
use tokio::io::AsyncReadExt;
use tracing::{debug, info, warn};

use crate::{
    analysis::{
        audit::run_cargo_audit,
        build_rs::analyze_build_rs,
        gitleaks::{run_gitleaks, GitleaksResult},
        llm::{run_llm_analysis, LlmAnalysisResult},
    },
    config::Config,
    database::Database,
    models::Crate,
    repositories::{
        download::download_repo,
        scan_results::get_crate_ids_needing_analysis,
    },
};

#[derive(Debug, Clone)]
struct ScanResultData {
    crate_id: i64,
    has_malicious_dependencies: bool,
    llm_malicious_score: i16,
    llm_notes: String,
    has_executable_files: bool,
    cargo_audit_max_dep_score: i16,
    cargo_audit_vulns_count: i16,
    build_rs_network_calls: bool,
    build_rs_has_link_directive: bool,
    build_rs_entropy_score: f32,
    build_rs_has_process_spawning: bool,
    build_rs_has_raw_ip: bool,
    build_rs_has_free_tlds: bool,
}

#[derive(Debug, Clone)]
struct AnalysisTiming {
    total_duration_ms: i64,
    cargo_audit_duration_ms: Option<i64>,
    gitleaks_duration_ms: Option<i64>,
    executable_check_duration_ms: Option<i64>,
    build_rs_analysis_duration_ms: Option<i64>,
    llm_analysis_duration_ms: Option<i64>,
    download_duration_ms: Option<i64>,
    worker_id: Option<String>,
    started_at: chrono::NaiveDateTime,
    completed_at: chrono::NaiveDateTime,
}

impl AnalysisTiming {
    fn placeholder() -> Self {
        let now = Utc::now().naive_utc();
        Self {
            total_duration_ms: 0,
            cargo_audit_duration_ms: None,
            gitleaks_duration_ms: None,
            executable_check_duration_ms: None,
            build_rs_analysis_duration_ms: None,
            llm_analysis_duration_ms: None,
            download_duration_ms: None,
            worker_id: current_worker_id(),
            started_at: now,
            completed_at: now,
        }
    }
}

fn current_worker_id() -> Option<String> {
    std::env::var("HOSTNAME").ok().filter(|s| !s.is_empty())
}

async fn measure_future_ms<F, T>(future: F) -> (T, i64)
where
    F: std::future::Future<Output = T>,
{
    let start = Instant::now();
    let output = future.await;
    (output, start.elapsed().as_millis() as i64)
}

#[derive(Debug, Clone)]
struct AnalysisResult {
    scan_result: ScanResultData,
    audit_results: Vec<(String, u8)>, // (rustsec_id, severity)
    gitleaks_results: Vec<GitleaksResult>,
    timing: AnalysisTiming,
}

pub async fn cleanup_cargo_caches() -> Result<(), anyhow::Error> {
    let dirs_to_delete = [
        // Note: /usr/local/cargo/registry and /usr/local/cargo/git are intentionally
        // excluded. They live on tmpfs and deleting them while another worker's
        // `cargo update --workspace` is downloading to them causes a
        // race condition that makes cargo-audit fail with ENOENT.
        // /usr/local/rustup is intentionally excluded - deleting it destroys the Rust toolchain.
        // /advisory-db is intentionally excluded - deleting it breaks cargo-audit
        // for all subsequent crates (used with --no-fetch --db /advisory-db).
        "/usr/local/cargo/target",
    ];

    let mut total_cleaned = 0u64;

    for dir in &dirs_to_delete {
        let path = std::path::Path::new(dir);
        if !path.exists() {
            continue;
        }

        let size_before = dir_size(path).await;

        if let Err(e) = remove_dir_all(path).await {
            warn!("Failed to remove {}: {:?}", dir, e);
        } else {
            total_cleaned += size_before;
        }
    }

    if total_cleaned > 0 {
        let cleaned_mb = total_cleaned as f64 / (1024.0 * 1024.0);
        info!("Cleaned {:.1} MB", cleaned_mb);
    }

    Ok(())
}

async fn dir_size(path: &std::path::Path) -> u64 {
    let mut size = 0u64;

    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if entry_path.is_dir() {
                size += Box::pin(dir_size(&entry_path)).await;
            } else if let Ok(metadata) = entry.metadata() {
                size += metadata.len();
            }
        }
    }

    size
}

/// Analyzes a single crate independently (no dependency traversal)
/// This is designed for distributed worker architecture where each crate is analyzed separately
pub async fn analyze_crate(c: &Crate, database: &Database, config: &Config) -> Result<(), anyhow::Error> {
    analyze_crate_inner(c, database, config, false, false).await
}

pub async fn analyze_crate_force(c: &Crate, database: &Database, config: &Config) -> Result<(), anyhow::Error> {
    analyze_crate_inner(c, database, config, true, true).await
}

async fn analyze_crate_inner(c: &Crate, database: &Database, config: &Config, force: bool, skip_audit: bool) -> Result<(), anyhow::Error> {
    if !force {
        let needs_analysis = get_crate_ids_needing_analysis(database, std::slice::from_ref(c))
            .await
            .context(format!("Failed to check if crate '{}' needs analysis", c.name))?;

        if !needs_analysis.contains(&c.id) {
            info!("Crate '{}' (id: {}) is already up-to-date, skipping", c.name, c.id);
            return Ok(());
        }
    }

    info!("Analyzing crate '{}' (id: {})", c.name, c.id);
    
    // Analyze just this crate - handle failures by inserting a failed placeholder
    let result = match analyze_single_crate(c, config, skip_audit).await {
        Ok(result) => result,
        Err(e) => {
            // Insert a "failed" placeholder to prevent re-scanning this crate forever
            // Use {:#} to show the full error chain including underlying causes
            let error_msg = format!("Analysis failed: {:#}", e);
            warn!("Crate '{}' (id: {}) failed analysis, inserting failed placeholder: {}", c.name, c.id, error_msg);
            AnalysisResult {
                scan_result: create_failed_placeholder_result(c.id, &error_msg),
                audit_results: Vec::new(),
                gitleaks_results: Vec::new(),
                timing: AnalysisTiming::placeholder(),
            }
        }
    };
    
    // Insert results immediately
    batch_insert_results(database, &[result])
        .await
        .context(format!("Failed to insert results for crate '{}'", c.name))?;
    
    info!("✓ Completed analysis for crate '{}' (id: {})", c.name, c.id);
    Ok(())
}

/// Analyzes a single crate by ID (wrapper for queue workers)
pub async fn analyze_crate_by_id(crate_id: i64, database: &Database, config: &Config) -> Result<(), anyhow::Error> {
    let crate_data = crate::repositories::crates::get_crate_by_id(database, crate_id)
        .await
        .context(format!("Failed to fetch crate with ID {}", crate_id))?;
    
    analyze_crate(&crate_data, database, config).await
}

async fn analyze_single_crate(crate_data: &Crate, config: &Config, skip_audit: bool) -> Result<AnalysisResult, anyhow::Error> {
    // Skip crates without a valid repository URL
    if crate_data.repository.is_empty() {
        info!("Skipping crate {} (id: {}) - no repository URL", crate_data.name, crate_data.id);
        // Mark it as processed
        return Ok(AnalysisResult {
            scan_result: create_placeholder_result(crate_data.id),
            audit_results: Vec::new(),
            gitleaks_results: Vec::new(),
            timing: AnalysisTiming::placeholder(),
        });
    }
    
    // Ensure uniqueness across workers
    let dir = format!("/tmp/crates/{}_{}", crate_data.name, crate_data.id);
    
    create_dir_all("/tmp/crates")
        .await
        .context("Failed to create /tmp/crates directory")?;
    
    // Clean up any existing directory from previous failed attempts
    if std::path::Path::new(&dir).exists() {
        debug!("Cleaning up existing directory: {}", dir);
        let _ = remove_dir_all(&dir).await;
    }
    
    let started_at = Utc::now().naive_utc();
    let total_start = Instant::now();
    let download_start = Instant::now();

    match download_repo(&crate_data.repository, &dir).await {
        Ok(_) => {
            let download_duration_ms = download_start.elapsed().as_millis() as i64;
            info!("Successfully downloaded crate '{}' (id: {}) to {}", crate_data.name, crate_data.id, dir);
            
            let result_data = perform_analysis(crate_data, &dir, config, skip_audit).await;
            
            if let Err(e) = remove_dir_all(&dir).await {
                warn!("Failed to clean up directory {}: {:?}", dir, e);
            }
            
            // Propagate the result
            let mut result_data = result_data
                .context(format!("Failed to perform analysis for crate '{}'", crate_data.name))?;

            result_data.timing.download_duration_ms = Some(download_duration_ms);
            result_data.timing.total_duration_ms = total_start.elapsed().as_millis() as i64;
            result_data.timing.started_at = started_at;
            result_data.timing.completed_at = Utc::now().naive_utc();
            
            info!("Completed analysis for crate: {} (id: {})", crate_data.name, crate_data.id);
            Ok(result_data)
        }
        Err(e) => {
            let download_duration_ms = download_start.elapsed().as_millis() as i64;
            let _ = remove_dir_all(&dir).await;
            
            // Check if it's a private/not found repository error
            if e.to_string().contains("private or not found") {
                info!("Skipping crate {} (id: {}) - repository is private or not found", crate_data.name, crate_data.id);
                // Mark as processed
                Ok(AnalysisResult {
                    scan_result: create_placeholder_result(crate_data.id),
                    audit_results: Vec::new(),
                    gitleaks_results: Vec::new(),
                    timing: AnalysisTiming {
                        total_duration_ms: total_start.elapsed().as_millis() as i64,
                        cargo_audit_duration_ms: None,
                        gitleaks_duration_ms: None,
                        executable_check_duration_ms: None,
                        build_rs_analysis_duration_ms: None,
                        llm_analysis_duration_ms: None,
                        download_duration_ms: Some(download_duration_ms),
                        worker_id: current_worker_id(),
                        started_at,
                        completed_at: Utc::now().naive_utc(),
                    },
                })
            } else {
                Err(e).context(format!("Failed to download repository for crate '{}'", crate_data.name))
            }
        }
    }
}

fn create_placeholder_result(crate_id: i64) -> ScanResultData {
    ScanResultData {
        crate_id,
        has_malicious_dependencies: false,
        llm_malicious_score: 0,
        llm_notes: "Skipped - no repository or private".to_string(),
        has_executable_files: false,
        cargo_audit_max_dep_score: 0,
        cargo_audit_vulns_count: 0,
        build_rs_network_calls: false,
        build_rs_has_link_directive: false,
        build_rs_entropy_score: 0.0,
        build_rs_has_process_spawning: false,
        build_rs_has_raw_ip: false,
        build_rs_has_free_tlds: false,
    }
}

fn create_failed_placeholder_result(crate_id: i64, error_msg: &str) -> ScanResultData {
    // Truncate error message
    let truncated_msg = if error_msg.len() > 500 {
        format!("{}...", &error_msg[..500])
    } else {
        error_msg.to_string()
    };
    ScanResultData {
        crate_id,
        has_malicious_dependencies: false,
        llm_malicious_score: -1, // Use -1 to indicate failed analysis
        llm_notes: truncated_msg,
        has_executable_files: false,
        cargo_audit_max_dep_score: 0,
        cargo_audit_vulns_count: 0,
        build_rs_network_calls: false,
        build_rs_has_link_directive: false,
        build_rs_entropy_score: 0.0,
        build_rs_has_process_spawning: false,
        build_rs_has_raw_ip: false,
        build_rs_has_free_tlds: false,
    }
}

/// Check for executable files in the crate directory
/// Detects files with executable permissions or binary file signatures (ELF, Mach-O, PE)
async fn check_executable_files(crate_dir: &str, crate_id: i64) -> Result<bool, anyhow::Error> {
    use std::os::unix::fs::PermissionsExt;
    use tokio::fs;

    info!("Checking executable files for crate {}", crate_id);

    // Locate potentially executable files
    let output = tokio::process::Command::new("find")
        .arg(crate_dir)
        .arg("-path")
        .arg("*/.git/*")
        .arg("-prune")
        .arg("-o")
        .arg("-type")
        .arg("f")
        .arg("(")
        .arg("-perm")
        .arg("/111")  // Any execute bit set
        .arg("-o")
        .arg("-name")
        .arg("*.exe")
        .arg("-o")
        .arg("-name")
        .arg("*.dll")
        .arg("-o")
        .arg("-name")
        .arg("*.so")
        .arg("-o")
        .arg("-name")
        .arg("*.dylib")
        .arg(")")
        .arg("-print0")
        .output()
        .await
        .context("Failed to run find command")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "find command failed for crate {}: {}",
            crate_id,
            stderr.trim()
        ));
    }

    let found_paths: Vec<&[u8]> = output
        .stdout
        .split(|b| *b == 0)
        .filter(|segment| !segment.is_empty())
        .collect();

    // Check each found file for binary signatures
    for path_bytes in found_paths {
        let path_str = String::from_utf8_lossy(path_bytes);
        let path = std::path::Path::new(path_str.as_ref());

        if !path.is_file() {
            continue;
        }

        // Read only the first bytes to check for binary signatures
        if let Ok(mut file) = fs::File::open(path).await {
            let mut header = [0u8; 8];
            let bytes_read = file.read(&mut header).await.unwrap_or(0);

            if bytes_read >= 4 {
                // ELF signature: 0x7F 'E' 'L' 'F'
                if header.starts_with(&[0x7F, 0x45, 0x4C, 0x46]) {
                    info!("Found ELF binary in crate {}: {}", crate_id, path_str);
                    return Ok(true);
                }

                // Mach-O signatures
                if header.starts_with(&[0xCA, 0xFE, 0xBA, 0xBE])  // Universal binary
                    || header.starts_with(&[0xFE, 0xED, 0xFA, 0xCE])  // Mach-O 32-bit
                    || header.starts_with(&[0xFE, 0xED, 0xFA, 0xCF])  // Mach-O 64-bit
                    || header.starts_with(&[0xCF, 0xFA, 0xED, 0xFE])  // Mach-O 64-bit (reverse)
                    || header.starts_with(&[0xCE, 0xFA, 0xED, 0xFE])  // Mach-O 32-bit (reverse)
                {
                    info!("Found Mach-O binary in crate {}: {}", crate_id, path_str);
                    return Ok(true);
                }

                // PE signature
                if header.starts_with(&[0x4D, 0x5A]) {
                    info!("Found PE/Windows binary in crate {}: {}", crate_id, path_str);
                    return Ok(true);
                }

                // WebAssembly binary: '\0asm'
                if header.starts_with(&[0x00, 0x61, 0x73, 0x6D]) {
                    info!("Found WebAssembly binary in crate {}: {}", crate_id, path_str);
                    return Ok(true);
                }
            }

            // Also check for shebang scripts that might be executable
            if bytes_read >= 2 && header.starts_with(&[0x23, 0x21]) {
                // Check if file has execute permission
                if let Ok(metadata) = fs::metadata(path).await  && metadata.permissions().mode() & 0o111 != 0 {
                        debug!("Found executable script in crate {}: {}", crate_id, path_str);
                        // Only flag actual binaries
                }
            }
        }
    }

    info!("Completed executable file check for crate {} - no binaries found", crate_id);
    Ok(false)
}

/// Do all analysis steps in parallel and aggregates results
async fn perform_analysis(
    crate_data: &Crate,
    crate_dir: &str,
    config: &Config,
    skip_audit: bool,
) -> Result<AnalysisResult, anyhow::Error> {
    let crate_id = crate_data.id;
    
    info!("Starting parallel analysis for crate {} (id: {})", crate_data.name, crate_id);

    let llm_future = async {
        if config.llm_enabled {
            run_llm_analysis(crate_dir, crate_data, config).await
        } else {
            info!("LLM analysis disabled, skipping for crate '{}'", crate_data.name);
            Ok(LlmAnalysisResult {
                malicious_score: 0,
                notes: "LLM analysis disabled".to_string(),
            })
        }
    };

    let audit_future = async {
        if skip_audit {
            info!("Skipping cargo audit for crate '{}'", crate_data.name);
            Ok::<Vec<(String, u8)>, anyhow::Error>(Vec::new())
        } else {
            run_cargo_audit(crate_dir, crate_id).await
        }
    };

    let (
        (audit_result, cargo_audit_duration_ms),
        (gitleaks_result, gitleaks_duration_ms),
        (exec_result, executable_check_duration_ms),
        (build_rs_result, build_rs_analysis_duration_ms),
        (llm_result, llm_analysis_duration_ms),
    ) = tokio::join!(
        measure_future_ms(audit_future),
        measure_future_ms(run_gitleaks(crate_dir)),
        measure_future_ms(check_executable_files(crate_dir, crate_id)),
        measure_future_ms(analyze_build_rs(crate_dir)),
        measure_future_ms(llm_future),
    );
    
    let audit_results = audit_result
        .context(format!("cargo audit failed for crate '{}'", crate_data.name))?;
    
    let gitleaks_results = gitleaks_result
        .context(format!("gitleaks failed for crate '{}'", crate_data.name))?;

    let has_executable_files = exec_result
        .context(format!("executable file check failed for crate '{}'", crate_data.name))?;
    
    let llm_analysis = llm_result
        .context(format!("LLM analysis failed for crate '{}'", crate_data.name))?;
    
    let build_rs_analysis = build_rs_result
        .context(format!("build.rs analysis failed for crate '{}'", crate_data.name))?;
    
    let cargo_audit_max_dep_score = *audit_results.iter().map(|(_, severity)| severity).max().unwrap_or(&0) as i16;
    let cargo_audit_vulns_count = audit_results.len() as i16;
    
    info!("All parallel analyses completed for crate '{}' (id: {}): {} vulnerabilities, {} secrets found, LLM score: {}, build.rs entropy: {:.2}", 
          crate_data.name, crate_id, cargo_audit_vulns_count, gitleaks_results.len(), llm_analysis.malicious_score, build_rs_analysis.entropy_score);
    
    Ok(AnalysisResult {
        scan_result: ScanResultData {
            crate_id,
            has_malicious_dependencies: false, // This would be computed from dependency analysis
            llm_malicious_score: llm_analysis.malicious_score,
            llm_notes: llm_analysis.notes,
            has_executable_files,
            cargo_audit_max_dep_score,
            cargo_audit_vulns_count,
            build_rs_network_calls: build_rs_analysis.has_network_calls,
            build_rs_has_link_directive: build_rs_analysis.has_link_directive,
            build_rs_entropy_score: build_rs_analysis.entropy_score,
            build_rs_has_process_spawning: build_rs_analysis.has_process_spawning,
            build_rs_has_raw_ip: build_rs_analysis.has_raw_ip,
            build_rs_has_free_tlds: build_rs_analysis.has_free_tlds,
        },
        audit_results,
        gitleaks_results,
        timing: AnalysisTiming {
            total_duration_ms: 0,
            cargo_audit_duration_ms: Some(cargo_audit_duration_ms),
            gitleaks_duration_ms: Some(gitleaks_duration_ms),
            executable_check_duration_ms: Some(executable_check_duration_ms),
            build_rs_analysis_duration_ms: Some(build_rs_analysis_duration_ms),
            llm_analysis_duration_ms: Some(llm_analysis_duration_ms),
            download_duration_ms: None,
            worker_id: current_worker_id(),
            started_at: Utc::now().naive_utc(),
            completed_at: Utc::now().naive_utc(),
        },
    })
}

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
                "({}, {}, {}, '{}', {}, {}, {}, {}, {}, {}, {}, {}, {})",
                s.crate_id,
                s.has_malicious_dependencies,
                s.llm_malicious_score,
                s.llm_notes.replace("'", "''"), // Escape single quotes
                s.has_executable_files,
                s.cargo_audit_max_dep_score,
                s.cargo_audit_vulns_count,
                s.build_rs_network_calls,
                s.build_rs_has_link_directive,
                s.build_rs_entropy_score,
                s.build_rs_has_process_spawning,
                s.build_rs_has_raw_ip,
                s.build_rs_has_free_tlds
            )
        })
        .collect();
    
    let scan_values_str = scan_values.join(", ");
    
    let scan_query = format!(
        "INSERT INTO scan_results (id, has_malicious_dependencies, llm_malicious_score, llm_notes, has_executable_files, cargo_audit_max_dep_score, cargo_audit_vulns_count, build_rs_network_calls, build_rs_has_link_directive, build_rs_entropy_score, build_rs_has_process_spawning, build_rs_has_raw_ip, build_rs_has_free_tlds)
         VALUES {}
         ON CONFLICT (id) DO UPDATE SET
            has_malicious_dependencies = EXCLUDED.has_malicious_dependencies,
            llm_malicious_score = EXCLUDED.llm_malicious_score,
            llm_notes = EXCLUDED.llm_notes,
            has_executable_files = EXCLUDED.has_executable_files,
            cargo_audit_max_dep_score = EXCLUDED.cargo_audit_max_dep_score,
            cargo_audit_vulns_count = EXCLUDED.cargo_audit_vulns_count,
            build_rs_network_calls = EXCLUDED.build_rs_network_calls,
            build_rs_has_link_directive = EXCLUDED.build_rs_has_link_directive,
            build_rs_entropy_score = EXCLUDED.build_rs_entropy_score,
            build_rs_has_process_spawning = EXCLUDED.build_rs_has_process_spawning,
            build_rs_has_raw_ip = EXCLUDED.build_rs_has_raw_ip,
            build_rs_has_free_tlds = EXCLUDED.build_rs_has_free_tlds",
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
        // Clear old audit results for these crates
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

    // Timing metrics for each analyzed crate
    let format_i64_opt = |v: Option<i64>| v.map(|x| x.to_string()).unwrap_or_else(|| "NULL".to_string());
    let format_text_opt = |v: Option<&str>| {
        v.map(|s| format!("'{}'", s.replace("'", "''")))
            .unwrap_or_else(|| "NULL".to_string())
    };

    let metrics_values: Vec<String> = results
        .iter()
        .map(|r| {
            let t = &r.timing;
            format!(
                "({}, {}, {}, {}, {}, {}, {}, {}, {}, '{}', '{}')",
                r.scan_result.crate_id,
                t.total_duration_ms,
                format_i64_opt(t.cargo_audit_duration_ms),
                format_i64_opt(t.gitleaks_duration_ms),
                format_i64_opt(t.executable_check_duration_ms),
                format_i64_opt(t.build_rs_analysis_duration_ms),
                format_i64_opt(t.llm_analysis_duration_ms),
                format_i64_opt(t.download_duration_ms),
                format_text_opt(t.worker_id.as_deref()),
                t.started_at,
                t.completed_at
            )
        })
        .collect();

    if !metrics_values.is_empty() {
        let metrics_query = format!(
            "INSERT INTO analysis_metrics (crate_id, total_duration_ms, cargo_audit_duration_ms, gitleaks_duration_ms, executable_check_duration_ms, build_rs_analysis_duration_ms, llm_analysis_duration_ms, download_duration_ms, worker_id, started_at, completed_at)
             VALUES {}",
            metrics_values.join(", ")
        );

        diesel::sql_query(&metrics_query)
            .execute(&mut conn)
            .await
            .context("Failed to insert analysis metrics")?;
    }
    
    Ok(())
}