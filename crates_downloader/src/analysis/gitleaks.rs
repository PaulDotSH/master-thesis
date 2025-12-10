use anyhow::Context;
use sonic_rs::{JsonContainerTrait, JsonValueTrait};
use tokio::process::Command;
use tracing::info;

#[derive(Debug, Clone)]
pub struct GitleaksResult {
    pub rule_id: String,
    pub secret: String,
    pub path: String,
    pub entropy: f64,
}

pub async fn run_gitleaks(crate_dir: &str) -> Result<Vec<GitleaksResult>, anyhow::Error> {
    info!("Running gitleaks for crate '{}'", crate_dir);
    
    // Verify the directory exists before running gitleaks
    if !std::path::Path::new(crate_dir).exists() {
        anyhow::bail!("Crate directory '{}' does not exist", crate_dir);
    }
    
    let output = Command::new("gitleaks")
        .arg("-f")
        .arg("json")
        .arg("-r")
        .arg("tmp.json")
        .arg("dir")
        .current_dir(crate_dir)
        .output()
        .await
        .context(format!("Failed to run gitleaks for crate '{}'", crate_dir))?;
    
    // Check if gitleaks command succeeded
    // gitleaks returns exit code 1 when leaks are found, which is not an error
    if !output.status.success() && output.status.code() != Some(1) {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("gitleaks command failed: {}", stderr);
    }
    
    let json_path = format!("{}/tmp.json", crate_dir);
    
    // Check if the output file exists before trying to read it
    if !std::path::Path::new(&json_path).exists() {
        // No output file means no leaks found
        info!("No gitleaks output file found for '{}' - no leaks detected", crate_dir);
        return Ok(Vec::new());
    }
    
    let json = std::fs::read_to_string(&json_path)
        .context(format!("Failed to read gitleaks output from '{}'", json_path))?;
    
    // Clean up the temporary file
    let _ = std::fs::remove_file(&json_path);
    
    let json: sonic_rs::Value = sonic_rs::from_str(&json)
        .context(format!("Failed to parse gitleaks JSON output for '{}'", crate_dir))?;

    let results = json.as_array()
        .context("Expected JSON array from gitleaks")?
        .iter()
        .map(|result| GitleaksResult {
            rule_id: result["RuleID"].as_str().unwrap_or("unknown").to_string(),
            secret: result["Secret"].as_str().unwrap_or("").to_string(),
            path: result["Fingerprint"].as_str().unwrap_or("").to_string(),
            entropy: result["Entropy"].as_f64().unwrap_or(0.0),
        })
        .collect();

    Ok(results)
}
