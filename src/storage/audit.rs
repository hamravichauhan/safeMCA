use anyhow::Result;
use chrono::Utc;
use hex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub server: String,
    pub tool: String,
    pub arguments: Value,
    pub status: String,
    pub reason: Option<String>,
    #[serde(default)]
    pub prev_hash: String,
    #[serde(default)]
    pub hash: String,
}

#[derive(Clone, Debug)]
pub struct AuditLogger {
    log_path: PathBuf,
}

impl AuditLogger {
    pub fn new(_server_name: &str) -> Self {
        Self::with_path(PathBuf::from(".mcp-guard/audit.jsonl"))
    }

    pub fn with_path(log_path: PathBuf) -> Self {
        if let Some(parent) = log_path.parent() {
            let _ = create_dir_all(parent);

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        Self { log_path }
    }

    /// Salted one-way cryptographic SHA-256 hash for sensitive tokens to enable
    /// security correlation without ever exposing plaintext secrets in logs.
    fn hash_secret(secret: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"safemca_audit_salt_v1:");
        hasher.update(secret.as_bytes());
        let full_hash = hex::encode(hasher.finalize());
        format!("[REDACTED_BY_SAFEMCA][HASH:{}]", &full_hash[..16])
    }

    /// Redacts tokens, passwords, and private keys from audit logs to prevent credential leakage
    pub fn sanitize_value(val: &Value) -> Value {
        match val {
            Value::String(s) => {
                if s.contains("ghp_")
                    || s.contains("sk-")
                    || s.contains("BEGIN PRIVATE KEY")
                    || s.to_lowercase().contains("bearer ")
                {
                    Value::String(Self::hash_secret(s))
                } else {
                    Value::String(s.clone())
                }
            }
            Value::Object(map) => {
                let mut new_map = serde_json::Map::new();
                for (k, v) in map {
                    let lower_k = k.to_lowercase();
                    if lower_k.contains("password")
                        || lower_k.contains("token")
                        || lower_k.contains("secret")
                        || lower_k.contains("credential")
                        || lower_k.contains("api_key")
                        || lower_k.contains("apikey")
                    {
                        let secret_val = match v {
                            Value::String(s) => Self::hash_secret(s),
                            _ => "[REDACTED_BY_SAFEMCA]".to_string(),
                        };
                        new_map.insert(k.clone(), Value::String(secret_val));
                    } else {
                        new_map.insert(k.clone(), Self::sanitize_value(v));
                    }
                }
                Value::Object(new_map)
            }
            Value::Array(arr) => Value::Array(arr.iter().map(Self::sanitize_value).collect()),
            other => other.clone(),
        }
    }

    fn compute_entry_hash(
        prev_hash: &str,
        timestamp: &str,
        server: &str,
        tool: &str,
        args: &Value,
        status: &str,
        reason: Option<&str>,
    ) -> String {
        let mut hasher = Sha256::new();
        let payload = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            prev_hash,
            timestamp,
            server,
            tool,
            serde_json::to_string(args).unwrap_or_default(),
            status,
            reason.unwrap_or("")
        );
        hasher.update(payload.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn get_last_hash(&self) -> String {
        let zero_hash = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        if !self.log_path.exists() {
            return zero_hash;
        }

        if let Ok(file) = File::open(&self.log_path) {
            let reader = BufReader::new(file);
            let mut last_valid_hash = None;
            for line in reader.lines().map_while(Result::ok) {
                if !line.trim().is_empty() {
                    if let Ok(entry) = serde_json::from_str::<AuditEntry>(&line) {
                        if !entry.hash.is_empty() {
                            last_valid_hash = Some(entry.hash);
                        }
                    }
                }
            }

            if let Some(h) = last_valid_hash {
                return h;
            }
        }

        zero_hash
    }

    pub fn log(&self, server: &str, tool: &str, arguments: &Value, status: &str, reason: Option<&str>) {
        let sanitized_args = Self::sanitize_value(arguments);
        let timestamp = Utc::now().to_rfc3339();
        let prev_hash = self.get_last_hash();
        let hash = Self::compute_entry_hash(
            &prev_hash,
            &timestamp,
            server,
            tool,
            &sanitized_args,
            status,
            reason,
        );

        let entry = AuditEntry {
            timestamp,
            server: server.to_string(),
            tool: tool.to_string(),
            arguments: sanitized_args,
            status: status.to_string(),
            reason: reason.map(|s| s.to_string()),
            prev_hash,
            hash,
        };

        if let Ok(line) = serde_json::to_string(&entry) {
            if let Some(parent) = self.log_path.parent() {
                let _ = create_dir_all(parent);
            }
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.log_path) {
                let _ = writeln!(file, "{}", line);

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&self.log_path, std::fs::Permissions::from_mode(0o600));
                }
            }
        }
    }

    pub fn read_recent(limit: usize) -> Result<Vec<AuditEntry>> {
        let path = Path::new(".mcp-guard/audit.jsonl");
        if !path.exists() {
            return Ok(Vec::new());
        }

        let content = std::fs::read_to_string(path)?;
        let mut entries = Vec::new();

        for line in content.lines().rev().take(limit) {
            if let Ok(entry) = serde_json::from_str::<AuditEntry>(line) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Cryptographically verifies the tamper-evident hash chain across the default audit log.
    pub fn verify_integrity() -> Result<(bool, usize)> {
        Self::verify_file(Path::new(".mcp-guard/audit.jsonl"))
    }

    /// Cryptographically verifies the tamper-evident hash chain in a specific log file.
    pub fn verify_file(path: &Path) -> Result<(bool, usize)> {
        if !path.exists() {
            return Ok((true, 0));
        }

        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut expected_prev_hash: Option<String> = None;
        let mut count = 0;

        for (idx, line_res) in reader.lines().enumerate() {
            let line = line_res?;
            if line.trim().is_empty() {
                continue;
            }

            let entry: AuditEntry = match serde_json::from_str(&line) {
                Ok(e) => e,
                Err(_) => continue, // Skip legacy pre-v0.1.1 unparseable entries
            };

            // Skip legacy unhashed records
            if entry.hash.is_empty() {
                continue;
            }

            // If this is the first hashed entry, initialize expected_prev_hash
            if expected_prev_hash.is_none() {
                expected_prev_hash = Some(entry.prev_hash.clone());
            }

            // 1. Verify previous hash chaining
            if Some(&entry.prev_hash) != expected_prev_hash.as_ref() {
                return Ok((false, idx + 1));
            }

            // 2. Recompute and verify current hash
            let computed_hash = Self::compute_entry_hash(
                &entry.prev_hash,
                &entry.timestamp,
                &entry.server,
                &entry.tool,
                &entry.arguments,
                &entry.status,
                entry.reason.as_deref(),
            );

            if entry.hash != computed_hash {
                return Ok((false, idx + 1));
            }

            expected_prev_hash = Some(entry.hash);
            count += 1;
        }

        Ok((true, count))
    }
}
