//! Build.rs Analysis Module
//!
//! Analyzes build.rs files for potentially suspicious patterns including:
//! - Network calls using common Rust libraries
//! - Link directives (#[link], cargo:rustc-link-*)
//! - High entropy (potential obfuscation)
//! - Process spawning (Command::new, exec, spawn)
//! - Raw IP addresses (excluding local/private ranges)
//! - Free/suspicious TLDs (.tk, .ml, .xyz, etc.)

use anyhow::Context;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;
use tracing::{debug, info};

/// Results from build.rs analysis
#[derive(Debug, Clone, Default)]
pub struct BuildRsAnalysisResult {
    /// True if build.rs contains network library usage (reqwest, hyper, curl, etc.)
    pub has_network_calls: bool,
    /// True if build.rs contains link directives (#[link], cargo:rustc-link-*)
    pub has_link_directive: bool,
    /// Shannon entropy score of build.rs content (0.0 - 8.0)
    pub entropy_score: f32,
    /// True if build.rs spawns processes (Command::new, exec, spawn)
    pub has_process_spawning: bool,
    /// True if build.rs contains non-local raw IP addresses
    pub has_raw_ip: bool,
    /// True if build.rs contains free/suspicious TLDs
    pub has_free_tlds: bool,
    /// General entropy score for the entire crate
    pub crate_entropy_score: f32,
}

/// Network libraries commonly used in Rust that could be suspicious in build.rs
const NETWORK_LIBRARIES: &[&str] = &[
    // HTTP clients
    "reqwest",
    "hyper",
    "curl",
    "ureq",
    "attohttpc",
    "surf",
    "isahc",
    "minreq",
    "awc",
    // Low-level networking
    "tokio::net",
    "std::net::TcpStream",
    "std::net::UdpSocket",
    "socket2",
    "mio",
    // Download utilities
    "download",
    "fetch",
    "wget",
    // HTTP-related
    "http::",
    "https::",
];

/// Analyzes build.rs file in the given crate directory
pub async fn analyze_build_rs(crate_dir: &str) -> Result<BuildRsAnalysisResult, anyhow::Error> {
    let build_rs_path = Path::new(crate_dir).join("build.rs");
    
    // Check if build.rs exists
    if !build_rs_path.exists() {
        debug!("No build.rs found in {}", crate_dir);
        // Return default result with crate entropy
        let crate_entropy = calculate_crate_entropy(crate_dir).await.unwrap_or(0.0);
        return Ok(BuildRsAnalysisResult {
            crate_entropy_score: crate_entropy,
            ..Default::default()
        });
    }
    
    info!("Analyzing build.rs in {}", crate_dir);
    
    let content = fs::read_to_string(&build_rs_path)
        .await
        .context(format!("Failed to read build.rs from {:?}", build_rs_path))?;
    
    // Run all checks
    let has_network_calls = check_network_calls(&content);
    let has_link_directive = check_link_directive(&content)?;
    let entropy_score = calculate_shannon_entropy(&content);
    let has_process_spawning = check_process_spawning(&content)?;
    let has_raw_ip = check_raw_ip_addresses(&content)?;
    let has_free_tlds = check_free_tlds(&content)?;
    let crate_entropy_score = calculate_crate_entropy(crate_dir).await.unwrap_or(0.0);
    
    let result = BuildRsAnalysisResult {
        has_network_calls,
        has_link_directive,
        entropy_score,
        has_process_spawning,
        has_raw_ip,
        has_free_tlds,
        crate_entropy_score,
    };
    
    info!(
        "build.rs analysis complete: network={}, link={}, entropy={:.2}, process={}, raw_ip={}, free_tlds={}",
        result.has_network_calls,
        result.has_link_directive,
        result.entropy_score,
        result.has_process_spawning,
        result.has_raw_ip,
        result.has_free_tlds
    );
    
    Ok(result)
}

/// Check for network library usage in build.rs
fn check_network_calls(content: &str) -> bool {
    for lib in NETWORK_LIBRARIES {
        if content.contains(lib) {
            debug!("Found network library usage: {}", lib);
            return true;
        }
    }
    false
}

/// Check for link directives using regex
/// Pattern: #[link] | cargo:rustc-link-lib | cargo:rustc-link-search
fn check_link_directive(content: &str) -> Result<bool, anyhow::Error> {
    let pattern = r#"#\[link\]|cargo:rustc-link-lib|cargo:rustc-link-search"#;
    let re = Regex::new(pattern).context("Failed to compile link directive regex")?;
    Ok(re.is_match(content))
}

/// Calculate Shannon entropy of the content
/// Returns a value between 0.0 (completely uniform) and 8.0 (maximum entropy for bytes)
fn calculate_shannon_entropy(content: &str) -> f32 {
    if content.is_empty() {
        return 0.0;
    }
    
    let bytes = content.as_bytes();
    let len = bytes.len() as f32;
    
    // Count byte frequencies
    let mut freq: HashMap<u8, usize> = HashMap::new();
    for &byte in bytes {
        *freq.entry(byte).or_insert(0) += 1;
    }
    
    // Calculate entropy
    let entropy: f32 = freq
        .values()
        .map(|&count| {
            let p = count as f32 / len;
            if p > 0.0 {
                -p * p.log2()
            } else {
                0.0
            }
        })
        .sum();
    
    entropy
}

/// Check for process spawning patterns
/// Pattern: Command::new | process::Command | std::process | exec | spawn
fn check_process_spawning(content: &str) -> Result<bool, anyhow::Error> {
    let pattern = r#"Command::new|process::Command|std::process::|\.exec\(|\.spawn\("#;
    let re = Regex::new(pattern).context("Failed to compile process spawning regex")?;
    Ok(re.is_match(content))
}

/// Check for raw IP addresses (excluding local/private ranges)
/// Excludes: 127.x.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 0.0.0.0
fn check_raw_ip_addresses(content: &str) -> Result<bool, anyhow::Error> {
    // First, find all IP address patterns
    let ip_pattern = r#"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b"#;
    let re = Regex::new(ip_pattern).context("Failed to compile IP address regex")?;
    
    for cap in re.captures_iter(content) {
        let full_match = cap.get(0).map(|m| m.as_str()).unwrap_or("");
        
        // Parse octets
        let octets: Vec<u8> = (1..=4)
            .filter_map(|i| cap.get(i)?.as_str().parse().ok())
            .collect();
        
        if octets.len() != 4 {
            continue;
        }
        
        // Check if it's a local/private IP range
        if is_local_ip(&octets) {
            debug!("Skipping local/private IP: {}", full_match);
            continue;
        }
        
        // Valid non-local IP address found
        debug!("Found non-local IP address: {}", full_match);
        return Ok(true);
    }
    
    Ok(false)
}

/// Check if an IP address is in a local/private range
fn is_local_ip(octets: &[u8]) -> bool {
    if octets.len() != 4 {
        return false;
    }
    
    let (a, b, _, _) = (octets[0], octets[1], octets[2], octets[3]);
    
    // 127.x.x.x (loopback)
    if a == 127 {
        return true;
    }
    
    // 10.x.x.x (private class A)
    if a == 10 {
        return true;
    }
    
    // 172.16.x.x - 172.31.x.x (private class B)
    if a == 172 && (16..=31).contains(&b) {
        return true;
    }
    
    // 192.168.x.x (private class C)
    if a == 192 && b == 168 {
        return true;
    }
    
    // 0.0.0.0 (unspecified)
    if a == 0 && b == 0 {
        return true;
    }
    
    // 169.254.x.x (link-local)
    if a == 169 && b == 254 {
        return true;
    }
    
    false
}

/// Check for free/suspicious TLDs that are commonly used in malicious domains
/// Pattern: .(tk|ml|ga|cf|gq|xyz|top|work|click|link|host)
fn check_free_tlds(content: &str) -> Result<bool, anyhow::Error> {
    let pattern = r#"\.(tk|ml|ga|cf|gq|xyz|top|work|click|link|host)\b"#;
    let re = Regex::new(pattern).context("Failed to compile free TLDs regex")?;
    Ok(re.is_match(content))
}

/// Calculate average entropy of all Rust source files in the crate
async fn calculate_crate_entropy(crate_dir: &str) -> Result<f32, anyhow::Error> {
    let mut total_entropy = 0.0f32;
    let mut file_count = 0u32;
    
    // Walk through the crate directory and find .rs files
    let mut dirs_to_scan = vec![crate_dir.to_string()];
    
    while let Some(dir) = dirs_to_scan.pop() {
        let mut entries = match fs::read_dir(&dir).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            
            if path.is_dir() {
                // Skip target, .git, and other non-source directories
                let dir_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if !["target", ".git", "node_modules", "vendor"].contains(&dir_name) {
                    dirs_to_scan.push(path.to_string_lossy().to_string());
                }
            } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
                if let Ok(content) = fs::read_to_string(&path).await {
                    let entropy = calculate_shannon_entropy(&content);
                    total_entropy += entropy;
                    file_count += 1;
                }
            }
        }
    }
    
    if file_count == 0 {
        return Ok(0.0);
    }
    
    Ok(total_entropy / file_count as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy() {
        // Empty string should have 0 entropy
        assert_eq!(calculate_shannon_entropy(""), 0.0);
        
        // Single repeated character should have 0 entropy
        assert_eq!(calculate_shannon_entropy("aaaaaaa"), 0.0);
        
        // Two equally frequent characters should have entropy of 1.0
        let entropy = calculate_shannon_entropy("abababab");
        assert!((entropy - 1.0).abs() < 0.01);
        
        // Random-looking string should have higher entropy
        let high_entropy = calculate_shannon_entropy("aZ9!bY8@cX7#dW6$");
        assert!(high_entropy > 3.0);
    }

    #[test]
    fn test_is_local_ip() {
        assert!(is_local_ip(&[127, 0, 0, 1]));
        assert!(is_local_ip(&[10, 0, 0, 1]));
        assert!(is_local_ip(&[172, 16, 0, 1]));
        assert!(is_local_ip(&[172, 31, 255, 255]));
        assert!(is_local_ip(&[192, 168, 1, 1]));
        assert!(is_local_ip(&[0, 0, 0, 0]));
        
        assert!(!is_local_ip(&[8, 8, 8, 8])); // Google DNS
        assert!(!is_local_ip(&[1, 1, 1, 1])); // Cloudflare DNS
        assert!(!is_local_ip(&[172, 15, 0, 1])); // Not in 172.16-31 range
        assert!(!is_local_ip(&[172, 32, 0, 1])); // Not in 172.16-31 range
    }

    #[test]
    fn test_check_network_calls() {
        assert!(check_network_calls("use reqwest;"));
        assert!(check_network_calls("let client = hyper::Client::new();"));
        assert!(check_network_calls("use std::net::TcpStream;"));
        assert!(!check_network_calls("fn main() { println!(\"hello\"); }"));
    }

    #[test]
    fn test_check_link_directive() {
        assert!(check_link_directive("#[link]").unwrap());
        assert!(check_link_directive("println!(\"cargo:rustc-link-lib=foo\");").unwrap());
        assert!(check_link_directive("println!(\"cargo:rustc-link-search=native=/usr/lib\");").unwrap());
        assert!(!check_link_directive("fn main() {}").unwrap());
    }

    #[test]
    fn test_check_process_spawning() {
        assert!(check_process_spawning("Command::new(\"ls\")").unwrap());
        assert!(check_process_spawning("use std::process::Command;").unwrap());
        assert!(check_process_spawning("cmd.spawn()").unwrap());
        assert!(!check_process_spawning("fn spawn_task() {}").unwrap()); // function name shouldn't match
    }

    #[test]
    fn test_check_raw_ip() {
        assert!(check_raw_ip_addresses("let ip = \"8.8.8.8\";").unwrap());
        assert!(check_raw_ip_addresses("connect to 1.2.3.4").unwrap());
        assert!(!check_raw_ip_addresses("let ip = \"127.0.0.1\";").unwrap());
        assert!(!check_raw_ip_addresses("let ip = \"192.168.1.1\";").unwrap());
        assert!(!check_raw_ip_addresses("let ip = \"10.0.0.1\";").unwrap());
        assert!(!check_raw_ip_addresses("let ip = \"172.16.0.1\";").unwrap());
    }

    #[test]
    fn test_check_free_tlds() {
        assert!(check_free_tlds("http://malware.tk").unwrap());
        assert!(check_free_tlds("download from evil.xyz").unwrap());
        assert!(check_free_tlds("callback.ml/api").unwrap());
        assert!(!check_free_tlds("https://example.com").unwrap());
        assert!(!check_free_tlds("crates.io").unwrap());
    }
}
