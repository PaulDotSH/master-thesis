use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::fs;
use tracing::{debug, info, warn};
use walkdir::WalkDir;

use crate::config::Config;
use crate::models::Crate;

/// System prompt for the LLM to analyze code for malicious behavior
const SYSTEM_PROMPT: &str = r#"You are an expert cyber security analyst. Analyze the provided code to find possible malicious behavior.

Specifically look for:
1. Executing files or launching processes in unexpected locations
2. Opening reverse shells or network backdoors
3. Downloading and executing remote code
4. Exfiltrating data to external servers
5. Obfuscated or suspicious code patterns
6. Unauthorized file system access or modifications
7. Credential theft or keylogging
8. Cryptocurrency mining code
9. Supply chain attack patterns

For each finding, explain:
- What the suspicious code does
- Why it's concerning
- The severity (low/medium/high/critical)

At the end, provide a malicious score from 0-100 where:
- 0-20: No suspicious behavior found
- 21-40: Minor concerns, likely false positives
- 41-60: Moderate concerns, warrants review
- 61-80: High likelihood of malicious behavior
- 81-100: Confirmed malicious behavior

Format your response as:
FINDINGS:
[List each finding]

SCORE: [number]
SUMMARY: [brief summary]"#;

/// Request structure for LM Studio API (OpenAI-compatible)
#[derive(Debug, Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatMessage>,
    max_tokens: u32,
    temperature: f32,
    stream: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ChatMessage {
    role: String,
    content: String,
}

/// Response structure from LM Studio API
#[derive(Debug, Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

/// Result of LLM analysis
#[derive(Debug, Clone)]
pub struct LlmAnalysisResult {
    pub malicious_score: i16,
    pub notes: String,
}

/// File extensions to analyze
const SOURCE_EXTENSIONS: &[&str] = &[
    "rs", "py", "js", "ts", "sh", "bash", "ps1", "bat", "cmd",
    "c", "cpp", "h", "hpp", "go", "java", "rb", "pl", "php",
    "toml", "yaml", "yml", "json", "xml", "Makefile", "Dockerfile",
];

/// Maximum file size to analyze (256KB)
const MAX_FILE_SIZE: u64 = 256 * 1024;

/// Collects all source files from a directory
async fn collect_source_files(crate_dir: &str) -> Result<Vec<(String, String)>, anyhow::Error> {
    let mut files = Vec::new();
    let crate_path = Path::new(crate_dir);
    
    for entry in WalkDir::new(crate_dir)
        .into_iter()
        .filter_entry(|e| {
            // Skip hidden directories, target/, and .git/
            let name = e.file_name().to_string_lossy();
            !name.starts_with('.') && name != "target" && name != "node_modules"
        })
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        
        // Skip directories
        if path.is_dir() {
            continue;
        }
        
        // Check if it's a source file we want to analyze
        let extension = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let filename = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        let should_analyze = SOURCE_EXTENSIONS.contains(&extension) 
            || filename == "Makefile" 
            || filename == "Dockerfile"
            || filename.ends_with(".rs")
            || filename == "build.rs";
        
        if !should_analyze {
            continue;
        }
        
        // Check file size
        let metadata = match fs::metadata(&path).await {
            Ok(m) => m,
            Err(_) => continue,
        };
        
        if metadata.len() > MAX_FILE_SIZE {
            debug!("Skipping large file: {:?} ({} bytes)", path, metadata.len());
            continue;
        }
        
        // Read file content
        let content = match fs::read_to_string(&path).await {
            Ok(c) => c,
            Err(e) => {
                debug!("Failed to read file {:?}: {}", path, e);
                continue;
            }
        };
        
        // Get relative path for better context
        let relative_path = path.strip_prefix(crate_path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string_lossy().to_string());
        
        files.push((relative_path, content));
    }
    
    Ok(files)
}

/// Formats files for LLM analysis with crate context
/// Returns a vector of batches, each fitting within max_content size
fn create_analysis_batches(crate_info: &Crate, files: &[(String, String)], max_content: usize) -> Vec<String> {
    let crate_context = format!(
        "=== CRATE CONTEXT ===\n\
         Name: {}\n\
         Repository: {}\n\
         Downloads: {}\n\
         Created: {}\n\
         Updated: {}\n\
         ======================\n\n",
        crate_info.name,
        crate_info.repository,
        crate_info.crate_downloads,
        crate_info.crate_created_at,
        crate_info.crate_updated_at
    );
    
    // Prioritize certain files (build.rs, main entry points)
    let priority_files: Vec<&str> = vec!["build.rs", "lib.rs", "main.rs", "mod.rs"];
    let mut sorted_files: Vec<&(String, String)> = files.iter().collect();
    sorted_files.sort_by(|a, b| {
        let a_priority = priority_files.iter().position(|p| a.0.ends_with(p)).unwrap_or(999);
        let b_priority = priority_files.iter().position(|p| b.0.ends_with(p)).unwrap_or(999);
        a_priority.cmp(&b_priority)
    });
    
    let mut batches = Vec::new();
    let mut current_batch = crate_context.clone();
    let base_size = crate_context.len();
    
    for (path, file_content) in sorted_files {
        let file_section = format!("\n=== FILE: {} ===\n{}\n", path, file_content);
        
        // If this single file is larger than max_content, split it into chunks
        if file_section.len() > max_content - base_size {
            // First, save current batch if it has content beyond context
            if current_batch.len() > base_size {
                batches.push(current_batch);
                current_batch = crate_context.clone();
            }
            
            // Split the large file into chunks
            let chunk_size = max_content - base_size - 200; // Leave room for headers
            let content_chars: Vec<char> = file_content.chars().collect();
            let total_chunks = content_chars.len().div_ceil(chunk_size);
            
            for (chunk_idx, chunk) in content_chars.chunks(chunk_size).enumerate() {
                let chunk_content: String = chunk.iter().collect();
                let chunk_section = format!(
                    "\n=== FILE: {} (Part {}/{}) ===\n{}\n",
                    path, chunk_idx + 1, total_chunks, chunk_content
                );
                
                let mut batch = crate_context.clone();
                batch.push_str(&chunk_section);
                batches.push(batch);
            }
        } else if current_batch.len() + file_section.len() > max_content {
            // Current batch is full, start a new one
            if current_batch.len() > base_size {
                batches.push(current_batch);
            }
            current_batch = crate_context.clone();
            current_batch.push_str(&file_section);
        } else {
            // Add to current batch
            current_batch.push_str(&file_section);
        }
    }
    
    // Don't forget the last batch
    if current_batch.len() > base_size {
        batches.push(current_batch);
    }
    
    // If no batches were created (empty crate), create one with just the context
    if batches.is_empty() {
        batches.push(crate_context);
    }
    
    batches
}

/// Parses the LLM response to extract the malicious score
fn parse_llm_response(response: &str) -> (i16, String) {
    // Try to find SCORE: pattern
    let score = response
        .lines()
        .find(|line| line.trim().starts_with("SCORE:"))
        .and_then(|line| {
            line.trim()
                .strip_prefix("SCORE:")
                .and_then(|s| s.trim().parse::<i16>().ok())
        })
        .unwrap_or(0);
    
    // Clamp score to valid range
    let score = score.clamp(0, 100);
    
    // Extract summary if present, otherwise use full response
    let notes = response
        .lines()
        .skip_while(|line| !line.trim().starts_with("SUMMARY:"))
        .skip(1)
        .take(10)
        .collect::<Vec<_>>()
        .join("\n")
        .trim()
        .to_string();
    
    let notes = if notes.is_empty() {
        // Take last part of response if no summary section
        response.chars().take(1000).collect()
    } else {
        notes
    };
    
    (score, notes)
}

/// Sends a single batch to the LLM and returns the result
async fn analyze_single_batch(
    batch_content: &str,
    batch_num: usize,
    total_batches: usize,
    config: &Config,
    client: &reqwest::Client,
) -> Result<(i16, String), anyhow::Error> {
    let user_message = if total_batches > 1 {
        format!(
            "Analyze the following Rust crate code for malicious behavior (Part {}/{}):\n\n{}",
            batch_num, total_batches, batch_content
        )
    } else {
        format!(
            "Analyze the following Rust crate for malicious behavior:\n\n{}",
            batch_content
        )
    };
    
    let request = ChatCompletionRequest {
        model: config.lm_studio_model.clone(),
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: SYSTEM_PROMPT.to_string(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: user_message,
            },
        ],
        max_tokens: config.llm_max_tokens,
        temperature: config.llm_temperature,
        stream: false,
    };
    
    let url = format!("{}/chat/completions", config.lm_studio_url);
    
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&request)
        .send()
        .await
        .context("Failed to send request to LM Studio")?;
    
    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        anyhow::bail!("LM Studio API error ({}): {}", status, error_text);
    }
    
    let completion: ChatCompletionResponse = response
        .json()
        .await
        .context("Failed to parse LM Studio response")?;
    
    let assistant_response = completion.choices
        .first()
        .map(|c| c.message.content.clone())
        .unwrap_or_default();
    
    Ok(parse_llm_response(&assistant_response))
}

/// Runs LLM analysis on a crate directory using LM Studio API
/// Splits large codebases into multiple batches and aggregates results
pub async fn run_llm_analysis(
    crate_dir: &str,
    crate_info: &Crate,
    config: &Config,
) -> Result<LlmAnalysisResult, anyhow::Error> {
    info!("Running LLM analysis for crate '{}' (id: {})", crate_info.name, crate_info.id);
    
    // Collect source files
    let files = collect_source_files(crate_dir)
        .await
        .context("Failed to collect source files")?;
    
    if files.is_empty() {
        info!("No source files found in crate '{}', skipping LLM analysis", crate_info.name);
        return Ok(LlmAnalysisResult {
            malicious_score: 0,
            notes: "No source files found to analyze".to_string(),
        });
    }
    
    info!("Found {} source files in crate '{}'", files.len(), crate_info.name);
    
    // Create batches that fit within context limits
    let batches = create_analysis_batches(crate_info, &files, config.llm_max_context_chars);
    let total_batches = batches.len();
    
    info!("Split crate '{}' into {} batch(es) for LLM analysis", crate_info.name, total_batches);
    
    // Create HTTP client with timeout
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300)) // 5 minute timeout per request
        .build()
        .context("Failed to create HTTP client")?;
    
    // Process each batch and aggregate results
    let mut max_score: i16 = 0;
    let mut all_notes = Vec::new();
    
    for (idx, batch) in batches.iter().enumerate() {
        let batch_num = idx + 1;
        debug!("Processing batch {}/{} for crate '{}' ({} chars)", 
               batch_num, total_batches, crate_info.name, batch.len());
        
        match analyze_single_batch(batch, batch_num, total_batches, config, &client).await {
            Ok((score, notes)) => {
                info!("Batch {}/{} for '{}': score={}", batch_num, total_batches, crate_info.name, score);
                
                // Take the maximum score across all batches
                if score > max_score {
                    max_score = score;
                }
                
                // Collect notes from batches that found something
                if score > 0 && !notes.is_empty() {
                    if total_batches > 1 {
                        all_notes.push(format!("[Batch {}/{}] {}", batch_num, total_batches, notes));
                    } else {
                        all_notes.push(notes);
                    }
                }
            }
            Err(e) => {
                warn!("Failed to analyze batch {}/{} for '{}': {:?}", 
                      batch_num, total_batches, crate_info.name, e);
                // Continue with other batches instead of failing completely
                all_notes.push(format!("[Batch {}/{}] Analysis failed: {}", batch_num, total_batches, e));
            }
        }
    }
    
    let combined_notes = if all_notes.is_empty() {
        "No suspicious findings".to_string()
    } else {
        all_notes.join("\n\n")
    };
    
    info!("LLM analysis complete for '{}': max_score={} from {} batch(es)", 
          crate_info.name, max_score, total_batches);
    
    Ok(LlmAnalysisResult {
        malicious_score: max_score,
        notes: combined_notes,
    })
}

/// Checks if LM Studio is available
pub async fn check_lm_studio_connection(config: &Config) -> Result<bool, anyhow::Error> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    
    let url = format!("{}/models", config.lm_studio_url);
    
    match client.get(&url).send().await {
        Ok(response) => Ok(response.status().is_success()),
        Err(e) => {
            warn!("LM Studio not available at {}: {}", config.lm_studio_url, e);
            Ok(false)
        }
    }
}
