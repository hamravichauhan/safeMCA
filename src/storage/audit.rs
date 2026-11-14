use anyhow::Result;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub server: String,
    pub tool: String,
    pub arguments: Value,
    pub status: String,
    pub reason: Option<String>,
}

pub struct AuditLogger {
    log_path: PathBuf,
}

impl AuditLogger {
    pub fn new(_server_name: &str) -> Self {
        let dir = PathBuf::from(".mcp-guard");
        let _ = create_dir_all(&dir);
        let log_path = dir.join("audit.jsonl");

        Self { log_path }
    }

    /// Redacts tokens, passwords, and private keys from audit logs to prevent credential leakage
    fn sanitize_value(val: &Value) -> Value {
        match val {
            Value::String(s) => {
                if s.contains("ghp_")
                    || s.contains("sk-")
                    || s.contains("BEGIN PRIVATE KEY")
                    || s.to_lowercase().contains("bearer ")
                {
                    Value::String("[REDACTED_BY_SAFEMCA]".to_string())
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
                        new_map.insert(k.clone(), Value::String("[REDACTED_BY_SAFEMCA]".to_string()));
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

    pub fn log(&self, server: &str, tool: &str, arguments: &Value, status: &str, reason: Option<&str>) {
        let sanitized_args = Self::sanitize_value(arguments);

        let entry = AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            server: server.to_string(),
            tool: tool.to_string(),
            arguments: sanitized_args,
            status: status.to_string(),
            reason: reason.map(|s| s.to_string()),
        };

        if let Ok(line) = serde_json::to_string(&entry) {
            if let Some(parent) = self.log_path.parent() {
                let _ = create_dir_all(parent);
            }
            if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&self.log_path) {
                let _ = writeln!(file, "{}", line);
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
}
