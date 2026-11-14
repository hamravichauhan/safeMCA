use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProjectConfig {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub allowed_paths: Vec<String>,
    #[serde(default)]
    pub blocked_paths: Vec<String>,
    #[serde(default)]
    pub sql_policy: Option<SqlPolicyConfig>,
    #[serde(default)]
    pub shell_policy: Option<ShellPolicyConfig>,
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SqlPolicyConfig {
    pub mode: Option<String>, // "read-only", "strict", etc.
    #[serde(default)]
    pub allow_tables: Vec<String>,
    #[serde(default)]
    pub block_tables: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShellPolicyConfig {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CircuitBreakerConfig {
    pub max_calls_per_minute: Option<usize>,
    pub max_identical_consecutive_calls: Option<usize>,
}

impl ProjectConfig {
    pub fn find_and_load(dir: &Path) -> Result<Option<Self>> {
        let candidates = [
            dir.join(".safemca.yml"),
            dir.join(".safemca.yaml"),
            dir.join(".mcp-guard.yml"),
            dir.join(".mcp-guard.yaml"),
        ];

        for path in &candidates {
            if path.exists() {
                let content = fs::read_to_string(path)?;
                let config: ProjectConfig = serde_yaml::from_str(&content)?;
                return Ok(Some(config));
            }
        }

        Ok(None)
    }

    pub fn load_or_default(dir: &Path) -> Self {
        Self::find_and_load(dir).unwrap_or(None).unwrap_or_default()
    }
}
