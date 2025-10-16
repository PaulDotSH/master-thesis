use std::fs::File;
use tracing::{info, error, debug};

pub struct CratesDownloader {}

impl CratesDownloader {
    pub async fn download_crates_db() -> Result<(), anyhow::Error> {
        info!("Starting download of crates.io database dump");
        let url = "https://static.crates.io/db-dump.tar.gz";
        
        let response = reqwest::get(url).await.map_err(|e| {
            error!("Failed to download from {}: {}", url, e);
            e
        })?;
        
        debug!("Download successful, reading response bytes");
        let bytes = response.bytes().await?;
        info!("Downloaded {} bytes", bytes.len());
        
        std::fs::write("db-dump.tar.gz", bytes)?;
        info!("Saved database dump to db-dump.tar.gz");
        Ok(())
    }

    pub fn extract_crates_db() -> Result<(), anyhow::Error> {
        info!("Extracting database dump archive");
        let tar_gz = File::open("db-dump.tar.gz").map_err(|e| {
            error!("Failed to open db-dump.tar.gz: {}", e);
            e
        })?;
        
        let tar = flate2::read::GzDecoder::new(tar_gz);
        let mut archive = tar::Archive::new(tar);
        std::fs::create_dir_all("./db-dump")?;
        
        archive.unpack("./db-dump").map_err(|e| {
            error!("Failed to extract archive: {}", e);
            e
        })?;
        
        info!("Successfully extracted database dump to ./db-dump");
        Ok(())
    }

    pub async fn cleanup_and_organize() -> Result<(), anyhow::Error> {
        info!("Cleaning up and organizing extracted files");
        let files_to_keep = vec![
            "crates.csv",
            "dependencies.csv",
            "crate_downloads.csv",
            "versions.csv",
        ];

        let db_dump_entries = std::fs::read_dir("./db-dump")?;
        for entry in db_dump_entries {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                debug!("Found directory: {:?}", path);

                let data_dir = path.join("data");
                if data_dir.exists() {
                    for file_name in &files_to_keep {
                        let source = data_dir.join(file_name);
                        let dest = std::path::Path::new("./db-dump").join(file_name);

                        if source.exists() {
                            debug!("Copying {} to destination", file_name);
                            std::fs::copy(&source, &dest)?;
                        } else {
                            error!("Expected file {} not found in data directory", file_name);
                        }
                    }
                }

                debug!("Removing temporary directory: {:?}", path);
                std::fs::remove_dir_all(&path)?;
            }
        }

        if std::path::Path::new("db-dump.tar.gz").exists() {
            debug!("Removing db-dump.tar.gz archive");
            std::fs::remove_file("db-dump.tar.gz")?;
        }

        info!("Cleanup and organization completed successfully");
        Ok(())
    }

    pub async fn prepare_source_data() -> Result<(), anyhow::Error> {
        info!("Preparing source data from crates.io");
        Self::download_crates_db().await?;
        Self::extract_crates_db()?;
        Self::cleanup_and_organize().await?;
        info!("Source data preparation completed");
        Ok(())
    }
}
