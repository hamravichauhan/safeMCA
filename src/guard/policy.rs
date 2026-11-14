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
    sql_comment_block_regex: Regex,
    sql_comment_line_regex: Regex,
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardPolicy {
    pub fn new() -> Self {
        Self {
            // Catches sensitive files, keys, tokens, and protected system paths
            sensitive_path_regex: Regex::new(
                r#"(?i)(\.ssh|\.aws|\.gnupg|/etc/|/proc/|/sys/|/dev/|windows/system32|\.env($|[\.\w\-])|id_rsa|id_ed25519|id_ecdsa|id_dsa|\.pem|\.key|\.p12|\.pfx|\.kdbx|\.kube/config|docker/config\.json|\.azure|\.gcloud|\.netrc|\.npmrc|\.git-credentials|\.bash_history|\.zsh_history|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|bearer\s+[a-z0-9_\-\.]{20,}|credentials)"#
            ).unwrap(),
            
            // Catches any directory traversal attempting to escape project root (e.g., ../, ..\, /..)
            // Prevents false positives on ellipsis (...) by requiring boundary or slash
            path_traversal_regex: Regex::new(r#"(\.\./|/\.\.|(^|/)\.\.$)"#).unwrap(),

            // Catches mutating or destructive SQL statements (DROP, TRUNCATE, DELETE FROM, ALTER, UPDATE, INSERT, CREATE)
            destructive_sql_regex: Regex::new(
                r#"(?i)\b(DROP\s+(TABLE|DATABASE|SCHEMA|VIEW|INDEX)|TRUNCATE(\s+TABLE)?|DELETE\s+FROM|ALTER\s+TABLE|UPDATE\s+\w+\s+SET|INSERT\s+INTO|CREATE\s+(TABLE|DATABASE))\b"#
            ).unwrap(),

            // Catches dangerous shell commands (rm with recursive flags, disk wipes, curl/wget pipes to shell)
            destructive_cmd_regex: Regex::new(
                r#"(?i)\b(rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*|--recursive)|mkfs|dd\s+if=|chmod\s+(-R\s+)?777|(curl|wget)\s+.*\|\s*(bash|sh|zsh)|wipefs|shred)\b"#
            ).unwrap(),

            // Broad matching for state-changing file & terminal tools
            write_tool_regex: Regex::new(
                r#"(?i)\b(write_file|create_file|delete_file|remove_file|edit_file|append_file|patch_file|save_file|overwrite_file|execute_bash|run_command|shell_exec|git_push|git_commit|git_reset|bash|sh|zsh|terminal|exec|execute|drop_table)\b"#
            ).unwrap(),

            // SQL comment normalizers to eliminate SQL comment evasion (e.g. DROP/**/TABLE)
            sql_comment_block_regex: Regex::new(r#"/\*[\s\S]*?\*/"#).unwrap(),
            sql_comment_line_regex: Regex::new(r#"--[^\r\n]*"#).unwrap(),
        }
    }

    /// Recursively decodes percent-encoded sequences (handles single, double, and triple encoding)
    fn decode_percent_recursive(input: &str) -> String {
        let mut current = input.to_string();
        for _ in 0..3 {
            let decoded = Self::decode_percent_once(&current);
            if decoded == current {
                break;
            }
            current = decoded;
        }
        current
    }

    fn decode_percent_once(input: &str) -> String {
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

    /// Strips comments and collapses whitespace to normalize SQL queries against obfuscation
    fn normalize_sql(&self, input: &str) -> String {
        let no_block = self.sql_comment_block_regex.replace_all(input, " ");
        let no_comments = self.sql_comment_line_regex.replace_all(&no_block, " ");
        no_comments.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Recursively extracts all unescaped string values from the JSON argument tree
    fn extract_all_strings(val: &Value, list: &mut Vec<String>) {
        match val {
            Value::String(s) => list.push(s.clone()),
            Value::Array(arr) => {
                for item in arr {
                    Self::extract_all_strings(item, list);
                }
            }
            Value::Object(map) => {
                for (k, v) in map {
                    list.push(k.clone());
                    Self::extract_all_strings(v, list);
                }
            }
            _ => {}
        }
    }

    pub fn evaluate(&self, tool_name: &str, arguments: &Value) -> PolicyDecision {
        let mut extracted_strings = Vec::new();
        Self::extract_all_strings(arguments, &mut extracted_strings);

        // Also check the stringified payload as fallback
        extracted_strings.push(arguments.to_string());

        for text in &extracted_strings {
            let decoded = Self::decode_percent_recursive(text);

            // Normalize slashes to forward slash and collapse multiple slashes
            let mut normalized_decoded = decoded.replace('\\', "/");
            while normalized_decoded.contains("//") {
                normalized_decoded = normalized_decoded.replace("//", "/");
            }

            // 1. Hard Block: Sensitive paths, credentials, or private keys
            if self.sensitive_path_regex.is_match(text)
                || self.sensitive_path_regex.is_match(&decoded)
                || self.sensitive_path_regex.is_match(&normalized_decoded)
            {
                return PolicyDecision::Block {
                    reason: "Access to sensitive file, credentials, or private keys is prohibited.".to_string(),
                };
            }

            // 2. Hard Block: Directory traversal (raw, decoded, or normalized)
            if self.path_traversal_regex.is_match(text)
                || self.path_traversal_regex.is_match(&decoded)
                || self.path_traversal_regex.is_match(&normalized_decoded)
            {
                return PolicyDecision::Block {
                    reason: "Directory traversal attack detected (attempting to escape workspace).".to_string(),
                };
            }

            // 3. Destructive SQL detection (with SQL comment stripping to prevent evasion like DROP/**/TABLE)
            let normalized_sql = self.normalize_sql(text);
            let normalized_decoded_sql = self.normalize_sql(&decoded);

            if self.destructive_sql_regex.is_match(&normalized_sql)
                || self.destructive_sql_regex.is_match(&normalized_decoded_sql)
            {
                return PolicyDecision::RequireApproval {
                    reason: format!("Destructive SQL query detected in tool '{}'", tool_name),
                };
            }

            // 4. Destructive shell command detection
            if self.destructive_cmd_regex.is_match(text)
                || self.destructive_cmd_regex.is_match(&decoded)
                || self.destructive_cmd_regex.is_match(&normalized_decoded)
            {
                return PolicyDecision::RequireApproval {
                    reason: format!("Potentially destructive shell command detected in tool '{}'", tool_name),
                };
            }
        }

        // 5. Any write / mutation tool -> Require Human Confirmation (The Airbag)
        if self.write_tool_regex.is_match(tool_name) {
            return PolicyDecision::RequireApproval {
                reason: format!("State-changing action requested by tool '{}'", tool_name),
            };
        }

        // 6. Default safe read-only tools
        PolicyDecision::Allow
    }
}
