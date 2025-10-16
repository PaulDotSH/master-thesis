use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub max_connections: u32,
    pub connection_string: String,
    pub llm_malicious_score_threshold: u8,
    pub update_source_data: bool,
    pub use_only_first_x_crates: u32,
    pub max_crates_downloads: u32,
    pub insert_crates_in_chunks: usize,
}

impl Default for Config {
    // If config file exists, load it, otherwise use default values
    fn default() -> Self {
        if let Ok(config) = Config::load() {
            return config;
        }

        let config = Self {
            max_connections: 5,
            connection_string: "postgres://postgres:postgres@localhost:5432/crates".to_string(),
            llm_malicious_score_threshold: 75,
            update_source_data: true,
            use_only_first_x_crates: 0,
            max_crates_downloads: 0,
            insert_crates_in_chunks: 1000,
        };
        config.save().expect("Failed to save config");
        config
    }
}

impl Config {
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
