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
            // Catches ~/.ssh, ~/.aws, ~/.gnupg, /etc/shadow, /etc/passwd, .env, private keys, cloud tokens, histories
            sensitive_path_regex: Regex::new(
                r#"(?i)(\.ssh|\.aws|\.gnupg|/etc/shadow|/etc/passwd|\.env($|[\.\w\-])|id_rsa|id_ed25519|id_ecdsa|id_dsa|\.pem|\.key|\.p12|\.pfx|\.kube[/\\]config|docker[/\\]config\.json|\.azure|\.gcloud|\.netrc|\.npmrc|\.git-credentials|\.bash_history|\.zsh_history|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|credentials)"#
            ).unwrap(),
            
            // Catches any directory traversal attempting to escape project root (e.g., ../, ..\, /..)
            path_traversal_regex: Regex::new(r#"(\.\.[/\\]|[/\\]\.\.|\.\.$)"#).unwrap(),

            // Catches destructive SQL statements (DROP, TRUNCATE with or without TABLE, DELETE FROM, ALTER TABLE)
            destructive_sql_regex: Regex::new(
                r#"(?i)\b(DROP\s+(TABLE|DATABASE|SCHEMA|VIEW|INDEX)|TRUNCATE(\s+TABLE)?|DELETE\s+FROM|ALTER\s+TABLE)\b"#
            ).unwrap(),

            // Catches dangerous shell commands (rm with recursive flags, disk wipes, curl/wget pipes to shell)
            destructive_cmd_regex: Regex::new(
                r#"(?i)\b(rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*|--recursive)|mkfs|dd\s+if=|chmod\s+(-R\s+)?777|(curl|wget)\s+.*\|\s*(bash|sh|zsh)|wipefs|shred)\b"#
            ).unwrap(),

            // Tools that modify the filesystem, run commands, or mutate state
            write_tool_regex: Regex::new(
                r#"(?i)(write_file|create_file|delete_file|remove_file|execute_bash|run_command|shell_exec|git_push)"#
            ).unwrap(),
        }
    }

    /// Decodes URL/percent-encoded sequences (e.g. %2e%2e%2f -> ../) to prevent encoding bypasses
    fn decode_percent_encoded(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let bytes = input.as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(hex_str) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                    if let Ok(byte_val) = u8::from_str_radix(hex_str, 16) {
                        result.push(byte_val as char);
                        i += 3;
                        continue;
                    }
                }
            }
            result.push(bytes[i] as char);
            i += 1;
        }

        result
    }

    pub fn evaluate(&self, tool_name: &str, arguments: &Value) -> PolicyDecision {
        let raw_args = arguments.to_string();
        // Decode percent-encoded payload to thwart evasion techniques
        let decoded_args = Self::decode_percent_encoded(&raw_args);

        // 1. Hard Block: Sensitive paths, credentials, or private keys
        if self.sensitive_path_regex.is_match(&raw_args) || self.sensitive_path_regex.is_match(&decoded_args) {
            return PolicyDecision::Block {
                reason: "Access to sensitive file, credentials, or private keys is prohibited.".to_string(),
            };
        }

        // 2. Hard Block: Directory traversal (raw or decoded)
        if self.path_traversal_regex.is_match(&raw_args) || self.path_traversal_regex.is_match(&decoded_args) {
            return PolicyDecision::Block {
                reason: "Directory traversal attack detected (attempting to escape workspace).".to_string(),
            };
        }

        // 3. Destructive SQL or Shell command -> Require Human Confirmation
        if self.destructive_sql_regex.is_match(&raw_args) || self.destructive_sql_regex.is_match(&decoded_args) {
            return PolicyDecision::RequireApproval {
                reason: format!("Destructive SQL query detected in tool '{}'", tool_name),
            };
        }

        if self.destructive_cmd_regex.is_match(&raw_args) || self.destructive_cmd_regex.is_match(&decoded_args) {
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
