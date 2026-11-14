use regex::Regex;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    RequireApproval { reason: String },
    Block { reason: String },
}

pub struct GuardPolicy {
    sensitive_path_regex: Regex,
    path_traversal_regex: Regex,
    destructive_sql_regex: Regex,
    destructive_cmd_regex: Regex,
    write_tool_regex: Regex,
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardPolicy {
    pub fn new() -> Self {
        Self {
            // Catches ~/.ssh, ~/.aws, ~/.gnupg, /etc/shadow, /etc/passwd, .env, id_rsa, id_ed25519, credentials
            sensitive_path_regex: Regex::new(
                r#"(?i)(\.ssh|\.aws|\.gnupg|/etc/shadow|/etc/passwd|\.env($|[\.\w])|id_rsa|id_ed25519|credentials)"#
            ).unwrap(),
            
            // Catches path traversal escaping the workspace (e.g., ../../..)
            path_traversal_regex: Regex::new(r#"(\.\.[/\\]){2,}"#).unwrap(),

            // Catches destructive SQL statements
            destructive_sql_regex: Regex::new(
                r#"(?i)\b(DROP\s+TABLE|DROP\s+DATABASE|TRUNCATE\s+TABLE|DELETE\s+FROM)\b"#
            ).unwrap(),

            // Catches dangerous shell commands
            destructive_cmd_regex: Regex::new(
                r#"(?i)\b(rm\s+-(rf|fr|r)|mkfs|dd\s+if=|chmod\s+-R\s+777|curl\s+.*\|\s*(bash|sh))\b"#
            ).unwrap(),

            // Tools that modify the filesystem, run commands, or mutate state
            write_tool_regex: Regex::new(
                r#"(?i)(write_file|create_file|delete_file|remove_file|execute_bash|run_command|shell_exec|git_push)"#
            ).unwrap(),
        }
    }

    pub fn evaluate(&self, tool_name: &str, arguments: &Value) -> PolicyDecision {
        let args_str = arguments.to_string();

        // 1. Hard Block: Sensitive paths or credentials
        if self.sensitive_path_regex.is_match(&args_str) {
            return PolicyDecision::Block {
                reason: "Access to sensitive file, credentials, or private keys is prohibited.".to_string(),
            };
        }

        // 2. Hard Block: Aggressive path traversal
        if self.path_traversal_regex.is_match(&args_str) {
            return PolicyDecision::Block {
                reason: "Directory traversal attack detected (attempting to escape workspace).".to_string(),
            };
        }

        // 3. Destructive SQL or Shell command -> Require Human Confirmation
        if self.destructive_sql_regex.is_match(&args_str) {
            return PolicyDecision::RequireApproval {
                reason: format!("Destructive SQL query detected in tool '{}'", tool_name),
            };
        }

        if self.destructive_cmd_regex.is_match(&args_str) {
            return PolicyDecision::RequireApproval {
                reason: format!("Potentially destructive shell command detected in tool '{}'", tool_name),
            };
        }

        // 4. Any write / mutation tool -> Require Human Confirmation (The Airbag)
        if self.write_tool_regex.is_match(tool_name) {
            return PolicyDecision::RequireApproval {
                reason: format!("State-changing action requested by tool '{}'", tool_name),
            };
        }

        // 5. Default safe read-only tools
        PolicyDecision::Allow
    }
}
