use tokio::process::Command;
use tracing::warn;

#[derive(Debug)]
pub enum DownloadError {
    PrivateOrNotFound(String),
    Other(String),
}

impl std::fmt::Display for DownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DownloadError::PrivateOrNotFound(msg) => write!(f, "Repository private or not found: {}", msg),
            DownloadError::Other(msg) => write!(f, "Download error: {}", msg),
        }
    }
}

impl std::error::Error for DownloadError {}

/// Sanitizes a repository URL to make it suitable for git clone
/// Handles common issues like:
/// - GitHub /tree/master/ paths (web URLs, not git URLs)
/// - GitHub /blob/ paths
/// - Trailing slashes
fn sanitize_git_url(url: &str) -> String {
    let mut sanitized = url.trim().to_string();
    
    // Remove trailing slash
    if sanitized.ends_with('/') {
        sanitized.pop();
    }
    
    // Handle GitHub web URLs with /tree/ or /blob/ paths
    // Example: https://github.com/user/repo/tree/master/subdir -> https://github.com/user/repo
    if let Some(tree_pos) = sanitized.find("/tree/") {
        sanitized.truncate(tree_pos);
    }
    if let Some(blob_pos) = sanitized.find("/blob/") {
        sanitized.truncate(blob_pos);
    }
    
    sanitized
}

/// Checks if git error indicates a private or non-existent repository
fn is_private_or_not_found_error(stderr: &str) -> bool {
    let stderr_lower = stderr.to_lowercase();
    stderr_lower.contains("repository not found")
        || stderr_lower.contains("could not read from remote repository")
        || stderr_lower.contains("access denied")
        || stderr_lower.contains("authentication failed")
        || stderr_lower.contains("permission denied")
        || stderr_lower.contains("fatal: repository")
}

pub async fn download_repo(url: &str, target_dir: &str) -> Result<(), anyhow::Error> {
    if url.is_empty() {
        return Err(anyhow::anyhow!("Repository URL is empty"));
    }
    
    // Sanitize the URL to handle common issues
    let sanitized_url = sanitize_git_url(url);
    
    let output = Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--single-branch")
        .arg("--no-tags")
        .arg(&sanitized_url)
        .arg(target_dir)
        .env("GIT_TERMINAL_PROMPT", "0")  // Disable prompts
        .output()
        .await?;
    
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        // Check if it's a private/not found repository
        if is_private_or_not_found_error(&stderr) {
            warn!("Skipping private/inaccessible repository: {}", sanitized_url);
            return Err(DownloadError::PrivateOrNotFound(
                format!("Repository {} is private or not found", sanitized_url)
            ).into());
        }
        
        // Other git errors
        return Err(DownloadError::Other(
            format!("Failed to clone repository {} (sanitized from {}): {}", sanitized_url, url, stderr)
        ).into());
    }
    
    Ok(())
}
