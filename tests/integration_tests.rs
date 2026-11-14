use safemca::core::protocol::ParsedMessage;
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
