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
use tracing::{error, info};
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
    /// Clear the entire queue (dangerous!)
    ClearQueue,
    /// Fix dependency cycles that block the queue
    FixCycles,
    /// Break complex dependency cycles (A→B→C→A) - more aggressive
    BreakCycles,
}

// TODO: Check tomorrow if DB update is working correctly

#[tokio::main]
async fn main() {
    // Set up logging to both file and console
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
            error!("Failed to create database connection: {}", e);
            panic!("Failed to create database");
        }
    };

    match cli.command {
        Commands::UpdateDatabase => {
            info!("Starting database update process");

            info!("Downloading the data from crates.io");
            if let Err(e) = downloader::CratesDownloader::prepare_source_data().await {
                error!("Failed to prepare source data from crates.io: {}", e);
                panic!("Failed to prepare source data from crates.io");
            }
            info!("Successfully downloaded and prepared source data");

            let crate_count = match repositories::crates::count_crates(&database).await {
                Ok(count) => count,
                Err(e) => {
                    error!("Failed to count crates: {}", e);
                    panic!("Failed to count crates");
                }
            };

            if crate_count == 0 {
                info!("Database is empty. Starting initial population");
                if let Err(e) = data_import::populate_db(&database, &config).await {
                    error!("Failed to populate database: {}", e);
                    panic!("Failed to populate database");
                }
                info!("Database population completed successfully");
            } else {
                info!(
                    "Database contains {} crates. Starting incremental update",
                    crate_count
                );
                if let Err(e) = data_import::update_db(&database, &config).await {
                    error!("Failed to update database: {}", e);
                    panic!("Failed to update database");
                }
                info!("Database update completed successfully");
            }
        }
        Commands::RunAnalysis => {
            info!("Starting analysis process - building dependency graph in Redis");
            
            // Get root crates (either top X by downloads or all crates)
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
            
            // Check which of these crates actually need analysis
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
            info!("✓ Dependency graph initialized: {}", stats);
            info!("Start workers with: cargo run --release -- worker");
            info!("Or scale with Docker: docker-compose up -d --scale worker=10");
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
            
            let mut consecutive_empty = 0;
            const MAX_EMPTY_CHECKS: u32 = 3;
            
            loop {
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
                            info!("All work completed! Final stats: {}", stats);
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
                
                // Analyze the crate
                let analysis_result = analysis::analysis::analyze_crate_by_id(crate_id, &database).await;
                
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
                
                // Log progress periodically
                if let Ok(stats) = queue.get_stats().await {
                    if stats.completed % 10 == 0 || stats.ready < 10 {
                        info!("{}", stats);
                    }
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
            
            info!("✓ Successfully computed has_malicious_dependencies for all crates");
        }
        Commands::QueueStatus => {
            info!("Checking queue status...");
            
            let mut queue = queue::WorkQueue::new(&config.redis_url)
                .await
                .expect("Failed to connect to Redis");
            
            let stats = queue.get_stats().await.expect("Failed to get stats");
            println!("\n=== Queue Status ===");
            println!("{}", stats);
            
            if queue.is_done().await.unwrap_or(false) {
                println!("\n✓ All work is complete!");
            } else if stats.ready == 0 && stats.in_progress == 0 && stats.completed < stats.total {
                println!("\n⚠ No work ready but not all complete - check for cycles or missing dependencies");
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
                println!("✓ Recovered {} stale items back to ready queue", recovered);
            } else {
                println!("No stale items found");
            }
            
            let stats = queue.get_stats().await.expect("Failed to get stats");
            println!("Current status: {}", stats);
        }
        Commands::ClearQueue => {
            println!("⚠ WARNING: This will clear ALL queue state!");
            println!("Press Ctrl+C within 5 seconds to cancel...");
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            
            let mut queue = queue::WorkQueue::new(&config.redis_url)
                .await
                .expect("Failed to connect to Redis");
            
            queue.clear_all()
                .await
                .expect("Failed to clear queue");
            
            println!("✓ Queue cleared");
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
                println!("✓ Fixed {} crates that were blocked by cycles", fixed);
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
            
            println!("✓ Broke {} cycle edges, {} crates newly ready", broken, fixed);
        }
    }

    info!("Application completed successfully");
}
