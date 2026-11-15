use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub struct ResponseCache {
    cache_dir: PathBuf,
}

impl Default for ResponseCache {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseCache {
    pub fn new() -> Self {
        let dir = PathBuf::from(".safemcp").join("cache");
        Self::with_dir(dir)
    }

    pub fn with_dir(cache_dir: PathBuf) -> Self {
        if !cache_dir.exists() {
            let _ = fs::create_dir_all(&cache_dir);
            #[cfg(unix)]
            {
                let _ = fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700));
            }
        }
        Self { cache_dir }
    }

    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
    }

    /// Stores the oversized response to disk and returns (sha256_hash, relative_cache_path, preview_text)
    pub fn store_and_summarize(
        &self,
        tool_name: &str,
        raw_content: &str,
        max_preview_lines: usize,
    ) -> Result<(String, PathBuf, String)> {
        // 1. Calculate SHA-256 of raw content
        let mut hasher = Sha256::new();
        hasher.update(raw_content.as_bytes());
        let hash = hex::encode(hasher.finalize());

        let filename = format!("{}_{}.txt", tool_name.replace(['/', '\\'], "_"), &hash[..16]);
        let target_path = self.cache_dir.join(&filename);

        // 2. Write raw content with restricted permissions
        fs::write(&target_path, raw_content)
            .with_context(|| format!("Failed to write cache file at {:?}", target_path))?;

        #[cfg(unix)]
        {
            let _ = fs::set_permissions(&target_path, fs::Permissions::from_mode(0o600));
        }

        // 3. Generate clean preview (first N lines)
        let lines: Vec<&str> = raw_content.lines().collect();
        let total_lines = lines.len();
        let preview_lines = lines.iter().take(max_preview_lines).copied().collect::<Vec<&str>>().join("\n");

        let byte_len = raw_content.len();
        let size_kb = (byte_len as f64) / 1024.0;

        let summary = format!(
            "[safeMCP Airbag] Tool '{}' output was truncated ({:.1} KB, {} lines) to protect LLM context.\n\
             Full output is cached at: {}\n\n\
             --- Truncated Preview (First {} lines) ---\n\
             {}\n\
             --- [End of Preview. Full data available in local cache] ---",
            tool_name,
            size_kb,
            total_lines,
            target_path.display(),
            max_preview_lines.min(total_lines),
            preview_lines
        );

        Ok((hash, target_path, summary))
    }
}
