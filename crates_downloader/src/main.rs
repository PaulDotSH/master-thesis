mod config;
mod csv_reader;
mod data_import;
mod database;
mod downloader;
mod models;
mod repositories;
mod schema;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "crates_downloader")]
#[command(about = "A tool for downloading and analyzing Rust crates", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Update the database with fresh data from crates.io
    UpdateDatabase,
    /// Run security and code analysis on downloaded crates
    RunAnalysis,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let config = config::Config::default();
    let database = database::Database::new(&config)
        .await
        .expect("Failed to create database");

    match cli.command {
        Commands::UpdateDatabase => {
            println!("Updating database...");
            
            // Download fresh data from crates.io
            downloader::CratesDownloader::prepare_source_data()
                .await
                .expect("Failed to prepare source data from crates.io");

            // Populate the database (will skip if already populated)
            let crate_count = repositories::crates::count_crates(&database)
                .await
                .expect("Failed to count crates");

            if crate_count == 0 {
                println!("Database is empty. Populating database...");
                data_import::populate_db(&database, &config)
                    .await
                    .expect("Failed to populate database");
            } else {
                println!("Database already contains {} crates. Skipping population.", crate_count);
            }
            
            println!("Database update completed.");
        }
        Commands::RunAnalysis => {
            println!("Running analysis...");
            // TODO: Implement analysis functionality
            println!("Analysis functionality not yet implemented.");
        }
    }
}
