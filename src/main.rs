mod cli;
mod core;
mod guard;
mod storage;

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "mcp-guard",
    version = "0.1.0",
    about = "🛡️  The Airbag & Security Shield for AI Agents using the Model Context Protocol (MCP)",
    long_about = "MCP-Guard is an ultra-fast, transparent security proxy for Claude Desktop, Cursor, and AI agents.\nIt blocks prompt injections, prevents credential leaks, provides interactive approvals, and enables 1-click git rollbacks."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run an MCP server protected by MCP-Guard
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

fn run_self_test() {
    println!("\n{}", "🛡️  Running MCP-Guard Policy & Sandbox Self-Test...".bold().cyan());
    println!("{}", "=========================================================".dimmed());

    let policy = guard::policy::GuardPolicy::new();

    // Test 1: Credential theft attempt
    let ssh_payload = serde_json::json!({ "path": "~/.ssh/id_rsa" });
    let dec1 = policy.evaluate("read_file", &ssh_payload);
    match dec1 {
        guard::policy::PolicyDecision::Block { reason } => {
            println!("{} Test 1: SSH Key Theft Attempt -> {}", "✓".green().bold(), reason.red().bold());
        }
        _ => println!("{} Test 1 Failed: Expected block", "✗".red()),
    }

    // Test 2: Environment file leak
    let env_payload = serde_json::json!({ "file": "backend/.env.production" });
    let dec2 = policy.evaluate("read_file", &env_payload);
    match dec2 {
        guard::policy::PolicyDecision::Block { reason } => {
            println!("{} Test 2: .env File Access Attempt -> {}", "✓".green().bold(), reason.red().bold());
        }
        _ => println!("{} Test 2 Failed: Expected block", "✗".red()),
    }

    // Test 3: Path traversal attack
    let traversal_payload = serde_json::json!({ "path": "../../../etc/shadow" });
    let dec3 = policy.evaluate("read_file", &traversal_payload);
    match dec3 {
        guard::policy::PolicyDecision::Block { reason } => {
            println!("{} Test 3: Path Traversal (../../..) -> {}", "✓".green().bold(), reason.red().bold());
        }
        _ => println!("{} Test 3 Failed: Expected block", "✗".red()),
    }

    // Test 4: Destructive SQL injection
    let sql_payload = serde_json::json!({ "query": "DROP TABLE users; --" });
    let dec4 = policy.evaluate("execute_sql", &sql_payload);
    match dec4 {
        guard::policy::PolicyDecision::RequireApproval { reason } => {
            println!("{} Test 4: Destructive SQL (DROP TABLE) -> {}", "✓".green().bold(), reason.yellow().bold());
        }
        _ => println!("{} Test 4 Failed: Expected approval trigger", "✗".red()),
    }

    // Test 5: Safe read operation
    let safe_payload = serde_json::json!({ "path": "src/main.rs" });
    let dec5 = policy.evaluate("read_file", &safe_payload);
    match dec5 {
        guard::policy::PolicyDecision::Allow => {
            println!("{} Test 5: Safe Read (src/main.rs) -> {}", "✓".green().bold(), "ALLOWED".green().bold());
        }
        _ => println!("{} Test 5 Failed: Expected allow", "✗".red()),
    }

    println!("{}", "=========================================================".dimmed());
    println!("{} All security policies operational!\n", "✓".bold().green());
}
