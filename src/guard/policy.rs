use crate::guard::config::ProjectConfig;
use regex::Regex;
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    RequireApproval { reason: String },
    Block { reason: String },
}

pub struct GuardPolicy {
    project_config: ProjectConfig,
    sensitive_path_regex: Regex,
    path_traversal_regex: Regex,
    destructive_sql_regex: Regex,
    mutation_sql_regex: Regex,
    destructive_cmd_regex: Regex,
    write_tool_regex: Regex,
    sql_comment_block_regex: Regex,
    sql_comment_line_regex: Regex,
    sql_mysql_comment_regex: Regex,
}

impl Default for GuardPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl GuardPolicy {
    pub fn new() -> Self {
        let dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let config = ProjectConfig::load_or_default(&dir);
        Self::with_config(config)
    }

    pub fn with_config(config: ProjectConfig) -> Self {
        Self {
            project_config: config,
            // Catches sensitive files, keys, tokens, dotfiles, and protected system paths
            sensitive_path_regex: Regex::new(
                r#"(?i)(\.ssh|\.aws|\.gnupg|/etc/|/proc/|/sys/|/dev/|windows/system32|system32/config|ntuser\.dat|\.env($|[\.\w\-])|\.git/config|\.bashrc|\.zshrc|\.bash_profile|\.zprofile|id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys|known_hosts|\.pem|\.key|\.p12|\.pfx|\.kdbx|\.kube/config|docker/config\.json|\.azure|\.gcloud|google-credentials|\.netrc|\.npmrc|\.git-credentials|\.bash_history|\.zsh_history|ghp_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{20,}|bearer\s+[a-z0-9_\-\.]{20,}|credentials)"#
            ).unwrap(),
            
            // Catches any directory traversal attempting to escape project root (e.g., ../, ..\, /.., ‥)
            // Prevents false positives on ellipsis (...) by requiring boundary or slash
            path_traversal_regex: Regex::new(r#"(\.\./|/\.\.|(^|/)\.\.$)"#).unwrap(),

            // Catches mutating or destructive SQL statements (DROP, TRUNCATE, DELETE FROM, ALTER, UPDATE, INSERT, CREATE)
            destructive_sql_regex: Regex::new(
                r#"(?i)\b(DROP\s+(TABLE|DATABASE|SCHEMA|VIEW|INDEX)|TRUNCATE(\s+TABLE)?|DELETE\s+FROM|ALTER\s+TABLE|UPDATE\s+\w+\s+SET|INSERT\s+INTO|CREATE\s+(TABLE|DATABASE))\b"#
            ).unwrap(),

            // General mutation SQL regex used for read-only enforcement
            mutation_sql_regex: Regex::new(
                r#"(?i)\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|DROP\s+|TRUNCATE|ALTER\s+TABLE|CREATE\s+)\b"#
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
            sql_mysql_comment_regex: Regex::new(r#"/\*![\s\S]*?\*/"#).unwrap(),
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

    /// Normalizes Unicode homoglyphs and trick characters that could be used to bypass regex filters
    fn normalize_unicode_tricks(s: &str) -> String {
        s.replace(['／', '＼'], "/")
            .replace('‥', "..")
            .replace('．', ".")
            .replace(['\u{200B}', '\u{200C}', '\u{200D}', '\u{FEFF}'], "") // Strip zero-width spaces
    }

    /// Strips comments, quotes, brackets, and collapses whitespace to normalize SQL queries against obfuscation
    fn normalize_sql(&self, input: &str) -> String {
        let no_mysql = self.sql_mysql_comment_regex.replace_all(input, " ");
        let no_block = self.sql_comment_block_regex.replace_all(&no_mysql, " ");
        let no_comments = self.sql_comment_line_regex.replace_all(&no_block, " ");
        let no_quotes = no_comments.replace(['`', '[', ']', '"'], " ");
        no_quotes.split_whitespace().collect::<Vec<_>>().join(" ")
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

        for raw_text in &extracted_strings {
            // 0. Anti-Injection: Null byte detection
            if raw_text.contains('\0') {
                return PolicyDecision::Block {
                    reason: "Null-byte injection attempt detected.".to_string(),
                };
            }

            let text = Self::normalize_unicode_tricks(raw_text);
            let decoded = Self::decode_percent_recursive(&text);

            if decoded.contains('\0') {
                return PolicyDecision::Block {
                    reason: "Null-byte injection attempt detected after decoding.".to_string(),
                };
            }

            // Normalize slashes to forward slash and collapse multiple slashes
            let mut normalized_decoded = decoded.replace('\\', "/");
            while normalized_decoded.contains("//") {
                normalized_decoded = normalized_decoded.replace("//", "/");
            }

            // -------------------------------------------------------------
            // Feature 1: Project-Level Policy Config (.safemca.yml) Checks
            // -------------------------------------------------------------

            // 1.1 Custom Blocked Paths
            for blocked in &self.project_config.blocked_paths {
                let clean_blocked = blocked.trim().trim_end_matches("/*").trim_end_matches("/**");
                if !clean_blocked.is_empty()
                    && (text.contains(clean_blocked)
                        || decoded.contains(clean_blocked)
                        || normalized_decoded.contains(clean_blocked))
                {
                    return PolicyDecision::Block {
                        reason: format!(
                            "Access to path blocked by project policy (.safemca.yml): '{}'",
                            blocked
                        ),
                    };
                }
            }

            // 1.2 Custom SQL Policy
            if let Some(ref sql_policy) = self.project_config.sql_policy {
                let normalized_sql = self.normalize_sql(&text);
                let normalized_decoded_sql = self.normalize_sql(&decoded);

                // Mode: read-only
                if sql_policy.mode.as_deref() == Some("read-only")
                    && (self.mutation_sql_regex.is_match(&normalized_sql)
                        || self.mutation_sql_regex.is_match(&normalized_decoded_sql))
                {
                    return PolicyDecision::Block {
                        reason: "Database mutation blocked: project policy (.safemca.yml) enforces read-only mode."
                            .to_string(),
                    };
                }

                // Forbidden tables
                for table in &sql_policy.block_tables {
                    if normalized_sql.to_lowercase().contains(&table.to_lowercase())
                        || normalized_decoded_sql.to_lowercase().contains(&table.to_lowercase())
                    {
                        return PolicyDecision::Block {
                            reason: format!(
                                "Access to table '{}' is restricted by project policy (.safemca.yml)",
                                table
                            ),
                        };
                    }
                }
            }

            // 1.3 Custom Shell Policy
            if let Some(ref shell_policy) = self.project_config.shell_policy {
                for blocked_cmd in &shell_policy.block {
                    let clean_cmd = blocked_cmd.trim().trim_end_matches(" *").trim_end_matches("/*");
                    if !clean_cmd.is_empty()
                        && (text.contains(clean_cmd) || decoded.contains(clean_cmd))
                    {
                        return PolicyDecision::Block {
                            reason: format!(
                                "Shell command blocked by project policy (.safemca.yml): '{}'",
                                blocked_cmd
                            ),
                        };
                    }
                }
            }

            // -------------------------------------------------------------
            // Standard Deterministic Sandboxing Rules
            // -------------------------------------------------------------

            // 2. Hard Block: Sensitive paths, credentials, or private keys
            if self.sensitive_path_regex.is_match(&text)
                || self.sensitive_path_regex.is_match(&decoded)
                || self.sensitive_path_regex.is_match(&normalized_decoded)
            {
                return PolicyDecision::Block {
                    reason: "Access to sensitive file, credentials, or private keys is prohibited.".to_string(),
                };
            }

            // 3. Hard Block: Directory traversal (raw, decoded, or normalized)
            if self.path_traversal_regex.is_match(&text)
                || self.path_traversal_regex.is_match(&decoded)
                || self.path_traversal_regex.is_match(&normalized_decoded)
            {
                return PolicyDecision::Block {
                    reason: "Directory traversal attack detected (attempting to escape workspace).".to_string(),
                };
            }

            // 4. Destructive SQL detection (with SQL comment stripping to prevent evasion like DROP/**/TABLE)
            let normalized_sql = self.normalize_sql(&text);
            let normalized_decoded_sql = self.normalize_sql(&decoded);

            if self.destructive_sql_regex.is_match(&normalized_sql)
                || self.destructive_sql_regex.is_match(&normalized_decoded_sql)
            {
                return PolicyDecision::RequireApproval {
                    reason: format!("Destructive SQL query detected in tool '{}'", tool_name),
                };
            }

            // 5. Destructive shell command detection
            if self.destructive_cmd_regex.is_match(&text)
                || self.destructive_cmd_regex.is_match(&decoded)
                || self.destructive_cmd_regex.is_match(&normalized_decoded)
            {
                return PolicyDecision::RequireApproval {
                    reason: format!("Potentially destructive shell command detected in tool '{}'", tool_name),
                };
            }
        }

        // 6. Any write / mutation tool -> Require Human Confirmation (The Airbag)
        if self.write_tool_regex.is_match(tool_name) {
            return PolicyDecision::RequireApproval {
                reason: format!("State-changing action requested by tool '{}'", tool_name),
            };
        }

        // 7. Default safe read-only tools
        PolicyDecision::Allow
    }
}
