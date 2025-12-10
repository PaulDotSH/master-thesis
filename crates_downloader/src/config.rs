use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub max_connections: u32,
    pub connection_string: String,
    pub redis_url: String,
    pub llm_malicious_score_threshold: u8,
    pub update_source_data: bool,
    pub use_only_first_x_crates: u32,
    pub max_crates_downloads: u32,
    pub insert_crates_in_chunks: usize,
}

impl Default for Config {
    // If config file exists, load it, otherwise use default values
    // Environment variables override config file values
    fn default() -> Self {
        let mut config = if let Ok(config) = Config::load() {
            config
        } else {
            Self {
                max_connections: 5,
                connection_string: "postgres://postgres:postgres@localhost:5432/crates".to_string(),
                redis_url: "redis://localhost:6379".to_string(),
                llm_malicious_score_threshold: 75,
                update_source_data: true,
                use_only_first_x_crates: 0,
                max_crates_downloads: 0,
                insert_crates_in_chunks: 1000,
            }
        };

        // Override with environment variables if present
        if let Ok(database_url) = std::env::var("DATABASE_URL") {
            config.connection_string = database_url;
        }
        if let Ok(redis_url) = std::env::var("REDIS_URL") {
            config.redis_url = redis_url;
        }
        
        config
    }
}

impl Config {
    #[allow(dead_code)]
    fn save(&self) -> Result<(), anyhow::Error> {
        let toml_string = toml::to_string_pretty(self)?;
        std::fs::write("config.toml", toml_string)?;
        Ok(())
    }

    fn load() -> Result<Self, anyhow::Error> {
        let content = std::fs::read_to_string("config.toml")?;
        let config: Config = toml::from_str(&content)?;
        if config.insert_crates_in_chunks < 1 {
            return Err(anyhow::anyhow!(
                "insert_crates_in_chunks must be greater than 0"
            ));
        }
        Ok(config)
    }
}
