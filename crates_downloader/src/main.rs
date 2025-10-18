mod config;
mod csv_reader;
mod analysis;
mod data_import;
mod database;
mod downloader;
mod models;
mod repositories;
mod schema;

use clap::{Parser, Subcommand};
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
    UpdateDatabase,
    RunAnalysis,
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
                }
                info!("Database update completed successfully");
            }
        }
        Commands::RunAnalysis => {
            info!("Starting analysis process");
            analysis::analysis::analyze_crates(&database, &config).await.expect("Failed to analyze crates");
        }
    }

    info!("Application completed successfully");
}
