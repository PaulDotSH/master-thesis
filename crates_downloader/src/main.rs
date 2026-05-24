mod config;
mod csv_reader;
mod analysis;
mod data_import;
mod database;
mod downloader;
mod models;
mod repositories;
mod schema;
mod queue;

use clap::{Parser, Subcommand};
use diesel_async::RunQueryDsl;
use tracing::{error, info, warn};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "crates_downloader")]
#[command(about = "A tool for downloading and analyzing Rust crates", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Download and update the database with crate data from crates.io
    UpdateDatabase,
    /// Build dependency graph and push crates to Redis for analysis
    RunAnalysis,
    /// Start a worker to process crates from the Redis queue
    Worker,
    /// Compute has_malicious_dependencies after all analysis is complete
    ComputeDependencies,
    /// Show queue status and statistics
    QueueStatus,
    /// Recover stale in-progress items (for crashed workers)
    RecoverStale,
    /// Clear the entire queue
    ClearQueue,
    /// Fix dependency cycles that block the queue
    FixCycles,
    /// Break complex dependency cycles (A→B→C→A)
    BreakCycles,
    /// Manually scan a single crate and all its dependencies with LLM analysis (sequential, single process)
    ScanCrate {
        /// Name of the crate to scan
        #[arg(short, long)]
        name: String,
    },
    /// Queue a single crate and its dependencies for distributed analysis by workers
    QueueCrate {
        /// Name of the crate to queue for analysis
        #[arg(short, long)]
        name: String,
    },
    /// Scan the most X vulnerable crates (by cargo-audit risk score) with LLM analysis
    ScanMostVulnerable {
        /// Number of most vulnerable crates to scan
        #[arg(short, long)]
        count: usize,
    },
    /// Check if LM Studio is available and properly set up
    CheckLlm,
    /// Scan all crates for potential typosquatting
    Typosquat {
        /// Minimum combined similarity score (0-100) to consider as potential typosquat
        #[arg(short, long, default_value = "75")]
        min_score: u8,
        /// Clear existing results before running
        #[arg(short, long)]
        clear: bool,
        /// Only compare against top N crates by downloads (0 = all)
        #[arg(short, long, default_value = "0")]
        top_crates: i64,
    },
}

#[tokio::main]
async fn main() {
    // Logging to file and console
    let file_appender = RollingFileAppender::new(Rotation::DAILY, "logs", "crates_downloader.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false),
        )
        .init();

    info!("Starting crates_downloader application");

    let cli = Cli::parse();
    let config = config::Config::default();
    let database = match database::Database::new(&config).await {
        Ok(db) => {
            info!("Successfully connected to database");
            db
        }
        Err(e) => {
            panic!("Failed to create database {}", e);
        }
    };

    match cli.command {
        Commands::UpdateDatabase => {
            info!("Starting database update process");

            info!("Downloading the data from crates.io");
            if let Err(e) = downloader::CratesDownloader::prepare_source_data().await {
                panic!("Failed to prepare source data from crates.io: {}", e);
            }
            info!("Successfully downloaded and prepared source data");

            let crate_count = match repositories::crates::count_crates(&database).await {
                Ok(count) => count,
                Err(e) => {
                    panic!("Failed to count crates: {}", e);
                }
            };

            if crate_count == 0 {
                info!("Database is empty. Starting initial population");
                if let Err(e) = data_import::populate_db(&database, &config).await {
                    panic!("Failed to populate database: {}", e);
                }
                info!("Database population completed successfully");
            } else {
                info!(
                    "Database contains {} crates. Starting incremental update",
                    crate_count
                );
                if let Err(e) = data_import::update_db(&database, &config).await {
                    panic!("Failed to update database: {}", e);
                }
                info!("Database update completed successfully");
            }
        }
        Commands::RunAnalysis => {
            info!("Starting analysis process - building dependency graph in Redis");
            
            // Get root crates (top X by downloads or all crates)
            let root_crates = if config.use_only_first_x_crates > 0 {
                repositories::crates::get_top_download_crates(&database, config.use_only_first_x_crates as i64)
                    .await
                    .expect("Failed to get top download crates")
            } else {
                repositories::crates::get_all_crates(&database)
                    .await
                    .expect("Failed to get all crates")
            };
            
            let root_crate_ids: Vec<i64> = root_crates.iter().map(|c| c.id).collect();
            info!("Starting with {} root crates", root_crate_ids.len());
            
            // Collect all transitive dependencies if we're doing a subset
            let (all_crate_ids, dependencies) = if config.use_only_first_x_crates > 0 {
                info!("Collecting transitive dependencies for {} root crates...", root_crate_ids.len());
                repositories::dependencies::collect_transitive_dependencies(&database, &root_crate_ids)
                    .await
                    .expect("Failed to collect transitive dependencies")
            } else {
                // For all crates, just fetch dependencies directly (no need for transitive collection)
                let crate_ids: Vec<i64> = root_crates.iter().map(|c| c.id).collect();
                let deps = repositories::dependencies::get_dependencies_for_crates(&database, &crate_ids)
                    .await
                    .expect("Failed to get dependencies");
                (crate_ids.into_iter().collect(), deps)
            };
            
            info!("Total crates to analyze (including transitive deps): {}", all_crate_ids.len());
            
            let all_crates_list = repositories::crates::get_crates_by_ids(&database, &all_crate_ids.iter().copied().collect::<Vec<_>>())
                .await
                .expect("Failed to get crate details");
            
            info!("Checking which crates need analyzing...");
            let crate_ids_needing_analysis = repositories::scan_results::get_crate_ids_needing_analysis(
                &database, 
                &all_crates_list.values().cloned().collect::<Vec<_>>()
            )
                .await
                .expect("Failed to get crate IDs needing analysis");
            
            let crate_ids: Vec<i64> = crate_ids_needing_analysis.iter().copied().collect();
            info!("Found {} crates needing analysis (out of {} total)", crate_ids.len(), all_crate_ids.len());
            
            if crate_ids.is_empty() {
                info!("No crates need analysis. All done!");
                return;
            }
            
            let filtered_dependencies: std::collections::HashMap<i64, Vec<i64>> = dependencies
                .into_iter()
                .filter(|(crate_id, _)| crate_ids_needing_analysis.contains(crate_id))
                .map(|(crate_id, deps)| {
                    let filtered_deps: Vec<i64> = deps
                        .into_iter()
                        .filter(|dep_id| crate_ids_needing_analysis.contains(dep_id))
                        .collect();
                    (crate_id, filtered_deps)
                })
                .collect();
            
            info!("Filtered dependency graph to {} crates needing analysis", filtered_dependencies.len());
            
            // Initialize dependency graph in Redis
            let mut queue = queue::WorkQueue::new(&config.redis_url)
                .await
                .expect("Failed to connect to Redis");
            
            queue.initialize_dependency_graph(&crate_ids, &filtered_dependencies)
                .await
                .expect("Failed to initialize dependency graph");
            
            let stats = queue.get_stats().await.expect("Failed to get stats");
            info!("Dependency graph initialized: {}", stats);
        }
        Commands::Worker => {
            info!("Starting worker process - consuming from Redis dependency graph");

            let mut queue = queue::WorkQueue::new(&config.redis_url)
                .await
                .expect("Failed to connect to Redis");

            // Show initial stats
            let stats = queue.get_stats().await.expect("Failed to get stats");
            info!("Queue status: {}", stats);

            // Check for and recover any stale in-progress items on startup
            let recovered = queue.recover_stale_items().await.unwrap_or(0);
            if recovered > 0 {
                info!("Recovered {} stale items from previous workers", recovered);
            }

            // Set up graceful shutdown handling
            let shutdown = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let shutdown_clone = shutdown.clone();

            tokio::spawn(async move {
                let ctrl_c = async {
                    tokio::signal::ctrl_c()
                        .await
                        .expect("Failed to install Ctrl+C handler");
                };

                #[cfg(unix)]
                let terminate = async {
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("Failed to install SIGTERM handler")
                        .recv()
                        .await;
                };

                #[cfg(not(unix))]
                let terminate = std::future::pending::<()>();

                tokio::select! {
                    _ = ctrl_c => {
                        info!("Received Ctrl+C, initiating graceful shutdown...");
                    }
                    _ = terminate => {
                        info!("Received SIGTERM, initiating graceful shutdown...");
                    }
                }

                shutdown_clone.store(true, std::sync::atomic::Ordering::SeqCst);
            });

            let mut consecutive_empty = 0;
            const MAX_EMPTY_CHECKS: u32 = 3;
            let mut current_crate_id: Option<i64> = None;

            // Cache cleanup every N crates analyzed by this worker
            const CACHE_CLEANUP_INTERVAL_CRATES: u32 = 100;
            let mut crates_since_cleanup: u32 = 0;

            // Run initial cache cleanup on startup
            if let Err(e) = analysis::analysis::cleanup_cargo_caches().await {
                warn!("Initial cache cleanup failed: {:?}", e);
            }

            loop {
                // Check for shutdown signal
                if std::sync::atomic::AtomicBool::load(&shutdown, std::sync::atomic::Ordering::SeqCst) {
                    info!("Shutdown signal received, stopping worker...");
                    
                    // If we have a crate in progress, requeue it
                    if let Some(crate_id) = current_crate_id {
                        info!("Requeuing in-progress crate {} back to queue", crate_id);
                        if let Err(e) = queue.requeue_item(crate_id).await {
                            error!("Failed to requeue crate {}: {:?}", crate_id, e);
                        }
                    }
                    info!("Worker shutdown complete");
                    break;
                }
                
                // Try to pop a ready crate (with timeout)
                let crate_id = match queue.pop_ready_crate_blocking(5.0).await {
                    Ok(Some(id)) => {
                        consecutive_empty = 0;
                        id
                    }
                    Ok(None) => {
                        // No work available - check if we're done
                        consecutive_empty += 1;
                        
                        let stats = queue.get_stats().await.expect("Failed to get stats");
                        
                        if queue.is_done().await.unwrap_or(false) {
                            info!("All work completed; Final stats: {}", stats);
                            break;
                        }
                        
                        if consecutive_empty >= MAX_EMPTY_CHECKS {
                            // Still have work but nothing ready - deps still processing
                            info!("Waiting for dependencies to complete... {}", stats);
                            consecutive_empty = 0;
                        }
                        
                        continue;
                    }
                    Err(e) => {
                        error!("Failed to pop work from queue: {:?}", e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                        continue;
                    }
                };
                
                info!("Worker picked up crate ID: {}", crate_id);

                // Isn't unused, is used for shutdown to reinsert the current crate to in progress
                current_crate_id = Some(crate_id);
                
                let analysis_result = analysis::analysis::analyze_crate_by_id(crate_id, &database, &config).await;
                current_crate_id = None;
                
                match analysis_result {
                    Ok(_) => {
                        // Mark as completed - this will make dependents ready
                        if let Err(e) = queue.mark_completed(crate_id).await {
                            error!("Failed to mark crate {} as completed: {:?}", crate_id, e);
                        }
                    }
                    Err(e) => {
                        error!("Failed to analyze crate {}: {:?}", crate_id, e);
                        // Mark as failed so dependents can still proceed
                        if let Err(e) = queue.mark_failed(crate_id).await {
                            error!("Failed to mark crate {} as failed: {:?}", crate_id, e);
                        }
                    }
                }
                
                if let Ok(stats) = queue.get_stats().await && (stats.completed % 10 == 0 || stats.ready < 10) {
                        info!("{}", stats);
                }

                crates_since_cleanup += 1;
                if crates_since_cleanup >= CACHE_CLEANUP_INTERVAL_CRATES {
                    info!("Running cache cleanup after {} crates...", crates_since_cleanup);
                    if let Err(e) = analysis::analysis::cleanup_cargo_caches().await {
                        warn!("Cache cleanup failed: {:?}", e);
                    }
                    crates_since_cleanup = 0;
                }
            }
        }
        Commands::ComputeDependencies => {
            info!("Computing has_malicious_dependencies for all crates");
            
            let mut conn = database.get_connection().await.expect("Failed to get DB connection");
            
            let query = "
                UPDATE scan_results sr
                SET has_malicious_dependencies = EXISTS (
                    SELECT 1 
                    FROM dependencies d
                    JOIN scan_results dep_sr ON d.dependency_id = dep_sr.id
                    WHERE d.crate_id = sr.id
                    AND (
                        dep_sr.llm_malicious_score > $1 OR
                        dep_sr.cargo_audit_vulns_count > 0
                    )
                )
            ";
            
            diesel::sql_query(query)
                .bind::<diesel::sql_types::SmallInt, _>(config.llm_malicious_score_threshold as i16)
                .execute(&mut conn)
                .await
                .expect("Failed to compute has_malicious_dependencies");
            
            info!("Successfully computed has_malicious_dependencies for all crates");
        }
        Commands::QueueStatus => {
            info!("Checking queue status...");
            
            let mut queue = queue::WorkQueue::new(&config.redis_url)
                .await
                .expect("Failed to connect to Redis");
            
            let stats = queue.get_stats().await.expect("Failed to get stats");
            println!("___Queue Status___");
            println!("{}", stats);
            
            if queue.is_done().await.unwrap_or(false) {
                println!("All work is complete");
            } else if stats.ready == 0 && stats.in_progress == 0 && stats.completed < stats.total {
                println!("No work ready but not all complete (cycles?)");
            }
        }
        Commands::RecoverStale => {
            info!("Recovering stale in-progress items...");
            
            let mut queue = queue::WorkQueue::new(&config.redis_url)
                .await
                .expect("Failed to connect to Redis");
            
            let recovered = queue.recover_stale_items()
                .await
                .expect("Failed to recover stale items");
            
            if recovered > 0 {
                println!("Recovered {} stale items back to ready queue", recovered);
            } else {
                println!("No stale items found");
            }
            
            let stats = queue.get_stats().await.expect("Failed to get stats");
            println!("Current status: {}", stats);
        }
        Commands::ClearQueue => {
            println!("This will clear ALL queue state!");
            println!("Press Ctrl+C within 5 seconds to cancel...");
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            
            let mut queue = queue::WorkQueue::new(&config.redis_url)
                .await
                .expect("Failed to connect to Redis");
            
            queue.clear_all()
                .await
                .expect("Failed to clear queue");
            
            println!("Queue cleared");
        }
        Commands::FixCycles => {
            info!("Detecting and fixing dependency cycles...");
            
            let mut queue = queue::WorkQueue::new(&config.redis_url)
                .await
                .expect("Failed to connect to Redis");
            
            let stats_before = queue.get_stats().await.expect("Failed to get stats");
            println!("Before: {}", stats_before);
            
            let fixed = queue.fix_dependency_cycles()
                .await
                .expect("Failed to fix cycles");
            
            let stats_after = queue.get_stats().await.expect("Failed to get stats");
            println!("After:  {}", stats_after);
            
            if fixed > 0 {
                println!("Fixed {} crates that were blocked by cycles", fixed);
            } else {
                println!("No cycle issues found");
            }
        }
        Commands::BreakCycles => {
            info!("Breaking complex dependency cycles...");
            
            let mut queue = queue::WorkQueue::new(&config.redis_url)
                .await
                .expect("Failed to connect to Redis");
            
            let stats_before = queue.get_stats().await.expect("Failed to get stats");
            println!("Before: {}", stats_before);
            
            let broken = queue.break_complex_cycles()
                .await
                .expect("Failed to break cycles");
            
            // Also run fix_dependency_cycles to move newly unblocked crates
            let fixed = queue.fix_dependency_cycles()
                .await
                .expect("Failed to fix remaining cycles");
            
            let stats_after = queue.get_stats().await.expect("Failed to get stats");
            println!("After:  {}", stats_after);
            
            println!("Broke {} cycle edges, {} crates newly ready", broken, fixed);
        }
        Commands::ScanCrate { name } => {
            info!("Starting manual scan for crate '{}' and its dependencies", name);
            
            // Check if LM Studio is available first if LLM is enabled
            if config.llm_enabled {
                if !analysis::llm::check_lm_studio_connection(&config).await.unwrap_or(false) {
                    error!("LM Studio is not available at {}. Please start LM Studio or configure a different URL.", config.lm_studio_url);
                    panic!("LM Studio not available");
                }
                info!("LM Studio connection verified at {}", config.lm_studio_url);
            } else {
                info!("LLM analysis is disabled in config");
            }
            
            // Get the crate from database by name
            let target_crate = repositories::crates::get_crate_by_name(&database, &name)
                .await
                .unwrap_or_else(|_| panic!("Failed to find crate '{}' in database. Make sure to run update-database first.", name));
            
            info!("Found crate '{}' (id: {})", target_crate.name, target_crate.id);
            
            // Get all dependencies of this crate (transitive)
            let (all_crate_ids, _dependencies) = repositories::dependencies::collect_transitive_dependencies(
                &database,
                &[target_crate.id]
            ).await.expect("Failed to collect dependencies");
            
            info!("Found {} crates to analyze (including {} dependencies)", 
                  all_crate_ids.len(), all_crate_ids.len() - 1);
            
            // Get crate details for all dependencies
            let all_crates = repositories::crates::get_crates_by_ids(
                &database, 
                &all_crate_ids.iter().copied().collect::<Vec<_>>()
            ).await.expect("Failed to get crate details");
            
            // Analyze dependencies first
            let mut dependency_crates: Vec<_> = all_crates.values()
                .filter(|c| c.id != target_crate.id)
                .cloned()
                .collect();
            
            // Sort by downloads (analyze most popular first
            dependency_crates.sort_by_key(|b| std::cmp::Reverse(b.crate_downloads));
            
            let total_deps = dependency_crates.len();
            info!("Analyzing {} dependencies first...", total_deps);
            
            for (i, dep_crate) in dependency_crates.iter().enumerate() {
                info!("[{}/{}] Analyzing dependency: {} (id: {})", 
                      i + 1, total_deps, dep_crate.name, dep_crate.id);
                
                if let Err(e) = analysis::analysis::analyze_crate(dep_crate, &database, &config).await {
                    error!("Failed to analyze dependency '{}': {:?}", dep_crate.name, e);
                    // Continue with other dependencies
                }
            }
            
            info!("Finished analyzing {} dependencies", total_deps);
            
            // Now analyze the target crate itself
            info!("Analyzing target crate: {} (id: {})", target_crate.name, target_crate.id);
            
            if let Err(e) = analysis::analysis::analyze_crate(&target_crate, &database, &config).await {
                error!("Failed to analyze target crate '{}': {:?}", target_crate.name, e);
                panic!("Failed to analyze target crate");
            }
            
            info!("Successfully completed scan for crate '{}' and all its dependencies!", name);
        }
        Commands::QueueCrate { name } => {
            info!("Queuing crate '{}' and its dependencies for distributed analysis", name);
            
            // Get the crate from database by name
            let target_crate = repositories::crates::get_crate_by_name(&database, &name)
                .await
                .unwrap_or_else(|_| panic!("Failed to find crate '{}' in database. Make sure to run update-database first.", name));
            
            info!("Found crate '{}' (id: {})", target_crate.name, target_crate.id);
            
            // Get all dependencies of this crate (transitive)
            let (all_crate_ids, dependencies) = repositories::dependencies::collect_transitive_dependencies(
                &database,
                &[target_crate.id]
            ).await.expect("Failed to collect dependencies");
            
            info!("Found {} crates (including {} dependencies)", 
                  all_crate_ids.len(), all_crate_ids.len() - 1);
            
            // Get crate details for all crates
            let all_crates = repositories::crates::get_crates_by_ids(
                &database, 
                &all_crate_ids.iter().copied().collect::<Vec<_>>()
            ).await.expect("Failed to get crate details");
            
            // Check which crates need analysis
            info!("Checking which crates need analyzing...");
            let crate_ids_needing_analysis = repositories::scan_results::get_crate_ids_needing_analysis(
                &database, 
                &all_crates.values().cloned().collect::<Vec<_>>()
            ).await.expect("Failed to get crate IDs needing analysis");
            
            let crate_ids: Vec<i64> = crate_ids_needing_analysis.iter().copied().collect();
            info!("Found {} crates needing analysis (out of {} total)", crate_ids.len(), all_crate_ids.len());
            
            if crate_ids.is_empty() {
                info!("No crates need analysis. All done!");
                return;
            }
            
            // Filter dependencies to only include crates that need analysis
            let filtered_dependencies: std::collections::HashMap<i64, Vec<i64>> = dependencies
                .into_iter()
                .filter(|(crate_id, _)| crate_ids_needing_analysis.contains(crate_id))
                .map(|(crate_id, deps)| {
                    let filtered_deps: Vec<i64> = deps
                        .into_iter()
                        .filter(|dep_id| crate_ids_needing_analysis.contains(dep_id))
                        .collect();
                    (crate_id, filtered_deps)
                })
                .collect();
            
            info!("Filtered dependency graph to {} crates needing analysis", filtered_dependencies.len());
            
            // Initialize dependency graph in Redis
            let mut queue = queue::WorkQueue::new(&config.redis_url)
                .await
                .expect("Failed to connect to Redis");
            
            queue.initialize_dependency_graph(&crate_ids, &filtered_dependencies)
                .await
                .expect("Failed to initialize dependency graph");
            
            let stats = queue.get_stats().await.expect("Failed to get stats");
            info!("Dependency graph initialized: {}", stats);
            println!("\n=== Crate '{}' queued for distributed analysis ===", name);
            println!("{}", stats);
        }
        Commands::ScanMostVulnerable { count } => {
            info!("Scanning top {} most vulnerable crates (by cargo-audit risk score) with LLM", count);

            if !config.llm_enabled {
                error!("LLM analysis is disabled in config. Enable it with llm_enabled = true");
                panic!("LLM analysis disabled");
            }

            if !analysis::llm::check_lm_studio_connection(&config).await.unwrap_or(false) {
                error!("LM Studio is not available at {}. Please start LM Studio or configure a different URL.", config.lm_studio_url);
                panic!("LM Studio not available");
            }
            info!("LM Studio connection verified at {}", config.lm_studio_url);

            let crate_ids = repositories::crates::get_most_vulnerable_crate_ids(&database, count as i64)
                .await
                .expect("Failed to fetch most vulnerable crate IDs");

            if crate_ids.is_empty() {
                info!("No vulnerable crates found. Make sure cargo-audit has been run first.");
                return;
            }

            info!("Found {} vulnerable crate IDs, fetching details...", crate_ids.len());

            let crates_map = repositories::crates::get_crates_by_ids(&database, &crate_ids)
                .await
                .expect("Failed to fetch crate details");

            let mut crates: Vec<_> = crates_map.values().cloned().collect();
            crates.sort_by_key(|c| crate_ids.iter().position(|id| *id == c.id));

            let total = crates.len();
            info!("Starting LLM scan of {} most vulnerable crates", total);

            for (i, c) in crates.iter().enumerate() {
                info!("[{}/{}] Scanning vulnerable crate: {} (id: {})",
                      i + 1, total, c.name, c.id);

                if let Err(e) = analysis::analysis::analyze_crate_force(c, &database, &config).await {
                    error!("Failed to analyze crate '{}': {:?}", c.name, e);
                }
            }

            info!("Completed LLM scan of {} most vulnerable crates", total);
        }
        Commands::CheckLlm => {
            info!("Checking LM Studio connection...");
            
            println!("LLM Analysis: {}", if config.llm_enabled { "ENABLED" } else { "DISABLED" });
            
            if !config.llm_enabled {
                println!("  Set llm_enabled = true in config.toml to enable LLM analysis");
                return;
            }
            
            match analysis::llm::check_lm_studio_connection(&config).await {
                Ok(true) => {
                    println!("LM Studio is available at {}", config.lm_studio_url);
                    println!("Model: {}", config.lm_studio_model);
                    println!("Max context: {} chars", config.llm_max_context_chars);
                }
                Ok(false) => {
                    println!("LM Studio is not responding at {}", config.lm_studio_url);
                    println!("Make sure LM Studio is running and a model is loaded.");
                }
                Err(e) => {
                    println!("Error checking LM Studio: {:?}", e);
                }
            }
        }
        Commands::Typosquat { min_score, clear, top_crates } => {
            info!("Starting typosquat detection analysis");
            println!("Typosquat Detection");
            println!("==================");
            println!("Minimum score: {}", min_score);
            println!("Top crates to compare: {}", if top_crates > 0 { top_crates.to_string() } else { "all".to_string() });

            if clear {
                info!("Clearing existing typosquat results...");
                let cleared = repositories::typosquat::clear_typosquat_results(&database)
                    .await
                    .expect("Failed to clear typosquat results");
                println!("Cleared {} existing results", cleared);
            }

            let target_crates = if top_crates > 0 {
                repositories::crates::get_top_download_crates(&database, top_crates)
                    .await
                    .expect("Failed to get top download crates")
            } else {
                repositories::crates::get_all_crates(&database)
                    .await
                    .expect("Failed to get all crates")
            };

            let all_crates = repositories::crates::get_all_crates(&database)
                .await
                .expect("Failed to get all crates");

            info!("Comparing {} crates against {} target crates", all_crates.len(), target_crates.len());
            println!("\nAnalyzing {} crates against {} targets (multithreaded)...", all_crates.len(), target_crates.len());

            const BATCH_SIZE: usize = 1000;

            // Create a set of target crate IDs for quick lookup
            let target_ids: std::collections::HashSet<i64> = target_crates.iter().map(|c| c.id).collect();

            // Use rayon for parallel processing
            use rayon::prelude::*;
            use std::sync::atomic::{AtomicUsize, Ordering};

            let processed = AtomicUsize::new(0);
            let total_found_atomic = AtomicUsize::new(0);
            let total_comparisons = all_crates.len();

            let all_results: Vec<models::NewTyposquatResult> = all_crates
                .par_iter()
                .flat_map(|crate_a| {
                    let current = processed.fetch_add(1, Ordering::Relaxed) + 1;
                    if current.is_multiple_of(10000) {
                        let found_so_far = AtomicUsize::load(&total_found_atomic, Ordering::Relaxed);
                        println!("Progress: {}/{} crates processed, ~{} typosquats found", 
                                 current, total_comparisons, found_so_far);
                    }

                    let mut local_results = Vec::new();

                    // Only check if this crate might be typosquatting a target
                    for target in &target_crates {
                        if crate_a.id == target.id {
                            continue;
                        }

                        // Skip if crate_a is also a target (don't compare targets with each other)
                        if target_ids.contains(&crate_a.id) && crate_a.crate_downloads >= target.crate_downloads {
                            continue;
                        }

                        // Check for typosquat
                        if let Some(score) = analysis::typosquat::check_typosquat(
                            &crate_a.name,
                            &target.name,
                            min_score,
                        ) {
                            local_results.push(models::NewTyposquatResult {
                                crate_id: crate_a.id,
                                similar_crate_id: target.id,
                                levenshtein_score: score.levenshtein as i16,
                                damerau_levenshtein_score: score.damerau_levenshtein as i16,
                                jaro_winkler_score: score.jaro_winkler as i16,
                                keyboard_distance_score: score.keyboard_distance as i16,
                                prefix_similarity_score: score.prefix_similarity as i16,
                                combined_score: score.combined as i16,
                            });
                            total_found_atomic.fetch_add(1, Ordering::Relaxed);
                        }
                    }

                    local_results
                })
                .collect();

            let total_found = all_results.len();
            println!("Processing complete. Inserting {} results...", total_found);

            for batch in all_results.chunks(BATCH_SIZE) {
                let inserted = repositories::typosquat::insert_typosquat_results(&database, batch)
                    .await
                    .expect("Failed to insert typosquat results");
                info!("Inserted {} typosquat results", inserted);
            }

            println!("\n=== Typosquat Detection Complete ===");
            println!("Total potential typosquats found: {}", total_found);

            let high_risk = repositories::typosquat::get_high_risk_typosquats(&database, 80)
                .await
                .expect("Failed to get high risk typosquats");

            if !high_risk.is_empty() {
                println!("\nHigh-risk typosquats (score >= 80):");
                println!("{:<20} {:<20} {:>5} {:>5} {:>5} {:>5} {:>5} {:>8}",
                         "Suspect", "Target", "Lev", "Dam", "JW", "Key", "Pfx", "Combined");

                // Get crate names for display
                let crate_ids: Vec<i64> = high_risk.iter()
                    .flat_map(|r| vec![r.crate_id, r.similar_crate_id])
                    .collect();
                let crates_map = repositories::crates::get_crates_by_ids(&database, &crate_ids)
                    .await
                    .expect("Failed to get crate details");

                for result in high_risk.iter().take(20) {
                    let suspect_name = crates_map.get(&result.crate_id)
                        .map(|c| c.name.as_str())
                        .unwrap_or("unknown");
                    let target_name = crates_map.get(&result.similar_crate_id)
                        .map(|c| c.name.as_str())
                        .unwrap_or("unknown");

                    println!("{:<20} {:<20} {:>5} {:>5} {:>5} {:>5} {:>5} {:>8}",
                             &suspect_name[..suspect_name.len().min(20)],
                             &target_name[..target_name.len().min(20)],
                             result.levenshtein_score,
                             result.damerau_levenshtein_score,
                             result.jaro_winkler_score,
                             result.keyboard_distance_score,
                             result.prefix_similarity_score,
                             result.combined_score);
                }

                if high_risk.len() > 20 {
                    println!("... and {} more high-risk typosquats", high_risk.len() - 20);
                }
            }
        }
    }
}
