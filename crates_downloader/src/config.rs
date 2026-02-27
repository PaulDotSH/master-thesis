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
    /// LM Studio API URL (OpenAI-compatible endpoint)
    #[serde(default = "default_lm_studio_url")]
    pub lm_studio_url: String,
    /// LM Studio model name to use
    #[serde(default = "default_lm_studio_model")]
    pub lm_studio_model: String,
    /// Maximum tokens for LLM response
    #[serde(default = "default_llm_max_tokens")]
    pub llm_max_tokens: u32,
    /// Temperature for LLM (0.0-1.0, lower = more deterministic)
    #[serde(default = "default_llm_temperature")]
    pub llm_temperature: f32,
    /// Maximum characters to send to LLM (roughly 4 chars per token)
    #[serde(default = "default_llm_max_context_chars")]
    pub llm_max_context_chars: usize,
    /// Enable/disable LLM analysis (computationally expensive)
    #[serde(default = "default_llm_enabled")]
    pub llm_enabled: bool,
}

fn default_lm_studio_url() -> String {
    "http://localhost:1234/v1".to_string()
}

fn default_lm_studio_model() -> String {
    "local-model".to_string()
}

fn default_llm_max_tokens() -> u32 {
    4096
}

fn default_llm_temperature() -> f32 {
    0.1
}

fn default_llm_max_context_chars() -> usize {
    24 * 1024 // 24KB, roughly 6K tokens
}

fn default_llm_enabled() -> bool {
    true
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
                lm_studio_url: default_lm_studio_url(),
                lm_studio_model: default_lm_studio_model(),
                llm_max_tokens: default_llm_max_tokens(),
                llm_temperature: default_llm_temperature(),
                llm_max_context_chars: default_llm_max_context_chars(),
                llm_enabled: default_llm_enabled(),
            }
        };

        // Override with environment variables if present
        if let Ok(database_url) = std::env::var("DATABASE_URL") {
            config.connection_string = database_url;
        }
        if let Ok(redis_url) = std::env::var("REDIS_URL") {
            config.redis_url = redis_url;
        }
        if let Ok(lm_studio_url) = std::env::var("LM_STUDIO_URL") {
            config.lm_studio_url = lm_studio_url;
        }
        if let Ok(lm_studio_model) = std::env::var("LM_STUDIO_MODEL") {
            config.lm_studio_model = lm_studio_model;
        }
        if let Ok(llm_enabled) = std::env::var("LLM_ENABLED") {
            config.llm_enabled = llm_enabled.to_lowercase() == "true" || llm_enabled == "1";
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
