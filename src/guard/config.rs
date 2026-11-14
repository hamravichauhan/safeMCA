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
    #[serde(default)]
    pub response_airbag: Option<ResponseAirbagConfig>,
    #[serde(default)]
    pub response_guard: Option<ResponseGuardConfig>,
    #[serde(default)]
    pub tool_router: Option<ToolRouterConfig>,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseAirbagConfig {
    pub max_bytes: Option<usize>,
    pub max_preview_lines: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResponseGuardConfig {
    pub scan_indirect_injection: Option<bool>,
    pub block_unicode_obfuscation: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolRouterConfig {
    pub minify_schemas: Option<bool>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub excluded_tools: Vec<String>,
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
