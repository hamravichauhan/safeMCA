pub mod cli;
pub mod core;
pub mod guard;
pub mod storage;

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "safemca",
    version = "0.1.0",
    about = "🛡️  The Airbag & Security Shield for AI Agents using the Model Context Protocol (MCP)",
    long_about = "safeMCA is an ultra-fast, transparent security proxy for Claude Desktop, Cursor, and AI agents.\nIt blocks prompt injections, prevents credential leaks, provides interactive approvals, and enables 1-click git rollbacks."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run an MCP server protected by safeMCA
    Run {
        /// Name or identifier for the target MCP server
        #[arg(short, long, default_value = "default")]
        server: String,

        /// The child MCP server command and arguments to execute
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Automatically find and protect Claude Desktop or Cursor MCP servers
    Wrap {
        /// Optional path to custom mcp config JSON
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Restore original un-wrapped Claude Desktop or Cursor configuration
    Unwrap {
        /// Optional path to custom mcp config JSON
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Take an explicit snapshot of the workspace before running an agent
    Snapshot,

    /// 1-Click Rollback: Revert file changes made by the AI agent
    Undo,

    /// Inspect the security audit trail of all intercepted tool calls
    Audit {
        /// Number of recent entries to show
        #[arg(short, long, default_value = "20")]
        tail: usize,
    },

    /// Run self-test verification of policy checks and sandbox rules
    Test,
}

pub async fn run_app() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { server, command } => {
            cli::run::execute(server, command).await?;
        }
        Commands::Wrap { config } => {
            cli::wrap::execute(config)?;
        }
        Commands::Unwrap { config } => {
            cli::unwrap::execute(config)?;
        }
        Commands::Snapshot => {
            cli::snapshot::execute()?;
        }
        Commands::Undo => {
            cli::undo::execute()?;
        }
        Commands::Audit { tail } => {
            cli::audit::execute(tail)?;
        }
        Commands::Test => {
            run_self_test();
        }
    }

    Ok(())
}

pub fn run_self_test() {
    println!("\n{}", "🛡️  Running safeMCA Security & Sandbox Test Suite (10 Checks)...".bold().cyan());
    println!("{}", "=========================================================================".dimmed());

    let policy = guard::policy::GuardPolicy::new();
    let mut passed = 0;
    let mut total = 0;

    let mut assert_check = |test_num: usize, name: &str, tool: &str, payload: serde_json::Value, expected: &str| {
        total += 1;
        let decision = policy.evaluate(tool, &payload);
        match (expected, decision) {
            ("BLOCK", guard::policy::PolicyDecision::Block { reason }) => {
                println!("{} Test {:02}: {} -> {}", "✓".green().bold(), test_num, name, reason.red().bold());
                passed += 1;
            }
            ("APPROVE", guard::policy::PolicyDecision::RequireApproval { reason }) => {
                println!("{} Test {:02}: {} -> {}", "✓".green().bold(), test_num, name, reason.yellow().bold());
                passed += 1;
            }
            ("ALLOW", guard::policy::PolicyDecision::Allow) => {
                println!("{} Test {:02}: {} -> {}", "✓".green().bold(), test_num, name, "ALLOWED".green().bold());
                passed += 1;
            }
            (exp, other) => {
                println!("{} Test {:02}: {} FAILED (Expected {}, got {:?})", "✗".red().bold(), test_num, name, exp, other);
            }
        }
    };

    // 1. SSH key theft
    assert_check(1, "SSH Key Exfiltration", "read_file", serde_json::json!({ "path": "~/.ssh/id_rsa" }), "BLOCK");

    // 2. Environment file leak
    assert_check(2, "Production .env Access", "read_file", serde_json::json!({ "file": "backend/.env.production" }), "BLOCK");

    // 3. Percent-encoded URL traversal attack
    assert_check(3, "URL-Encoded Traversal (%2e%2e%2f)", "read_file", serde_json::json!({ "path": "%2e%2e%2f%2e%2e%2fetc/passwd" }), "BLOCK");

    // 4. Single relative path traversal
    assert_check(4, "Single Path Traversal (../)", "read_file", serde_json::json!({ "path": "../secrets.txt" }), "BLOCK");

    // 5. Cloud token / GitHub token in payload
    assert_check(5, "GitHub Token Exfiltration", "save_data", serde_json::json!({ "token": "ghp_123456789012345678901234567890123456" }), "BLOCK");

    // 6. Private TLS key access
    assert_check(6, "TLS Private Key Access", "read_file", serde_json::json!({ "cert": "ssl/server.key" }), "BLOCK");

    // 7. Destructive SQL with TRUNCATE without TABLE keyword
    assert_check(7, "Destructive SQL (TRUNCATE users;)", "execute_sql", serde_json::json!({ "query": "TRUNCATE users;" }), "APPROVE");

    // 8. Destructive SQL with DROP VIEW
    assert_check(8, "Destructive SQL (DROP VIEW)", "execute_sql", serde_json::json!({ "query": "DROP VIEW active_accounts;" }), "APPROVE");

    // 9. Dangerous shell command with split flags (rm -r -f)
    assert_check(9, "Destructive Shell (rm -r -f /var)", "execute_bash", serde_json::json!({ "command": "rm -r -f /var/cache" }), "APPROVE");

    // 10. Safe read operation
    assert_check(10, "Safe Read Operation (SELECT)", "execute_sql", serde_json::json!({ "query": "SELECT id, name FROM users WHERE id = 42;" }), "ALLOW");

    println!("{}", "=========================================================================".dimmed());
    if passed == total {
        println!("{} All {}/{} security & functionality test cases PASSED flawlessly!\n", "✓".bold().green(), passed, total);
    } else {
        println!("{} {}/{} test cases failed.\n", "✗".bold().red(), total - passed, total);
    }
}
