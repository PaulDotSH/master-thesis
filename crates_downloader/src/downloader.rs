use std::fs::File;

pub struct CratesDownloader {}

impl CratesDownloader {
    pub async fn download_crates_db() -> Result<(), anyhow::Error> {
        let url = "https://static.crates.io/db-dump.tar.gz";
        let response = reqwest::get(url).await?;
        let bytes = response.bytes().await?;
        std::fs::write("db-dump.tar.gz", bytes)?;
        Ok(())
    }

    pub fn extract_crates_db() -> Result<(), anyhow::Error> {
        let tar_gz = File::open("db-dump.tar.gz")?;
        let tar = flate2::read::GzDecoder::new(tar_gz);
        let mut archive = tar::Archive::new(tar);
        std::fs::create_dir_all("./db-dump")?;
        archive.unpack("./db-dump")?;
        Ok(())
    }

    pub async fn cleanup_and_organize() -> Result<(), anyhow::Error> {
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
                println!("Found directory: {:?}", path);

                let data_dir = path.join("data");
                if data_dir.exists() {
                    for file_name in &files_to_keep {
                        let source = data_dir.join(file_name);
                        let dest = std::path::Path::new("./db-dump").join(file_name);

                        if source.exists() {
                            std::fs::copy(&source, &dest)?;
                        }
                    }
                }

                std::fs::remove_dir_all(&path)?;
            }
        }

        if std::path::Path::new("db-dump.tar.gz").exists() {
            std::fs::remove_file("db-dump.tar.gz")?;
        }

        Ok(())
    }

    pub async fn prepare_source_data() -> Result<(), anyhow::Error> {
        Self::download_crates_db().await?;
        Self::extract_crates_db()?;
        Self::cleanup_and_organize().await?;
        Ok(())
    }
}
