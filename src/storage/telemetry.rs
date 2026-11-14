use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelemetryStats {
    pub total_calls: usize,
    pub allowed_calls: usize,
    pub blocked_calls: usize,
    pub user_approved_calls: usize,
    pub user_denied_calls: usize,
    pub circuit_breaker_trips: usize,
    pub prompt_injections_blocked: usize,
    pub airbag_truncations: usize,
    pub schema_minifications: usize,
    pub bytes_saved_airbag: usize,
    pub bytes_saved_minifier: usize,
    pub active_servers: Vec<String>,
}

pub struct TelemetryCollector;

impl TelemetryCollector {
    /// Computes telemetry statistics directly from audit logs and cache directory
    pub fn compute_stats(workspace_dir: &Path) -> TelemetryStats {
        let mut stats = TelemetryStats::default();

        let audit_file = workspace_dir.join(".mcp-guard").join("audit.jsonl");
        if audit_file.exists() {
            if let Ok(file) = fs::File::open(&audit_file) {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    if let Ok(entry) = serde_json::from_str::<serde_json::Value>(&line) {
                        stats.total_calls += 1;

                        if let Some(srv) = entry.get("server").and_then(|s| s.as_str()) {
                            if !stats.active_servers.iter().any(|s| s == srv) {
                                stats.active_servers.push(srv.to_string());
                            }
                        }

                        let status = entry.get("status").and_then(|s| s.as_str()).unwrap_or("");
                        match status {
                            "ALLOWED" => stats.allowed_calls += 1,
                            "BLOCKED" => {
                                stats.blocked_calls += 1;
                                if let Some(reason) = entry.get("reason").and_then(|r| r.as_str()) {
                                    if reason.contains("Prompt injection") || reason.contains("Indirect prompt injection") {
                                        stats.prompt_injections_blocked += 1;
                                    }
                                }
                            }
                            "USER_APPROVED" => stats.user_approved_calls += 1,
                            "USER_DENIED" => stats.user_denied_calls += 1,
                            "CIRCUIT_BREAKER_TRIPPED" => stats.circuit_breaker_trips += 1,
                            "INDIRECT_PROMPT_INJECTION_BLOCKED" => {
                                stats.blocked_calls += 1;
                                stats.prompt_injections_blocked += 1;
                            }
                            "AIRBAG_TRUNCATED" => stats.airbag_truncations += 1,
                            "SCHEMA_MINIFIED" => stats.schema_minifications += 1,
                            _ => {}
                        }
                    }
                }
            }
        }

        // Count cached items and calculate estimated bytes saved
        let cache_dir = workspace_dir.join(".safemca").join("cache");
        if cache_dir.exists() {
            if let Ok(entries) = fs::read_dir(cache_dir) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        let len = meta.len() as usize;
                        if len > 32768 {
                            stats.airbag_truncations += 1;
                            stats.bytes_saved_airbag += len.saturating_sub(4096);
                        }
                    }
                }
            }
        }

        stats
    }

    pub fn audit_log_path(workspace_dir: &Path) -> PathBuf {
        workspace_dir.join(".mcp-guard").join("audit.jsonl")
    }
}
