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
/// - GitHub /tree/master/
/// - GitHub /blob/
/// - Trailing slashes
fn sanitize_git_url(url: &str) -> String {
    let mut sanitized = url.trim().to_string();
    
    // Remove trailing slash
    if sanitized.ends_with('/') {
        sanitized.pop();
    }
    
    if let Some(tree_pos) = sanitized.find("/tree/") {
        sanitized.truncate(tree_pos);
    }
    if let Some(blob_pos) = sanitized.find("/blob/") {
        sanitized.truncate(blob_pos);
    }
    
    sanitized
}

fn is_private_or_not_found_error(stderr: &str) -> bool {
    let stderr_lower = stderr.to_lowercase();
    stderr_lower.contains("repository not found")
        || stderr_lower.contains("could not read from remote repository")
        || stderr_lower.contains("access denied")
        || stderr_lower.contains("authentication failed")
        || stderr_lower.contains("permission denied")
        || stderr_lower.contains("fatal: repository")
}

async fn try_clone(url: &str, target_dir: &str, filter: bool) -> Result<(), String> {
    let mut cmd = Command::new("git");
    cmd.arg("clone")
        .arg("--depth")
        .arg("1")
        .arg("--single-branch")
        .arg("--no-tags");

    if filter {
        cmd.arg("--filter=blob:none");
    }

    cmd.arg(url)
        .arg(target_dir)
        .env("GIT_TERMINAL_PROMPT", "0");

    let output = cmd.output().await.map_err(|e| e.to_string())?;

    if output.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

pub async fn download_repo(url: &str, target_dir: &str) -> Result<(), anyhow::Error> {
    if url.is_empty() {
        return Err(anyhow::anyhow!("Repository URL is empty"));
    }

    let sanitized_url = sanitize_git_url(url);

    // Try with --filter=blob:none first for efficiency
    if let Err(_) = try_clone(&sanitized_url, target_dir, true).await {
        // Fall through to retry without filter
    } else {
        return Ok(());
    }

    // If that failed, retry without --filter=blob:none
    // Some repositories don't support partial clone
    let stderr = match try_clone(&sanitized_url, target_dir, false).await {
        Ok(()) => return Ok(()),
        Err(e) => {
            // Use the error from the non-filter attempt since it's more informative
            e
        }
    };

    if is_private_or_not_found_error(&stderr) {
        warn!("Skipping private/inaccessible repository: {}", sanitized_url);
        return Err(DownloadError::PrivateOrNotFound(
            format!("Repository {} is private or not found", sanitized_url)
        ).into());
    }

    Err(DownloadError::Other(
        format!("Failed to clone repository {} (sanitized from {}): {}", sanitized_url, url, stderr)
    ).into())
}
