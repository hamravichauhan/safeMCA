use crate::storage::audit::AuditLogger;
use anyhow::Result;
use colored::Colorize;

pub fn execute(limit: usize) -> Result<()> {
    let entries = AuditLogger::read_recent(limit)?;

    if entries.is_empty() {
        println!("{}", "No audit logs found yet. Start running MCP servers with mcp-guard to see logs.".yellow());
        return Ok(());
    }

    println!("\n{}", "🛡️  MCP-Guard Security Audit Trail".bold().cyan());
    println!("{}", "=========================================================================================".dimmed());
    println!(
        "{:<20} {:<15} {:<20} {:<15} {}",
        "TIMESTAMP".bold(),
        "SERVER".bold(),
        "TOOL".bold(),
        "STATUS".bold(),
        "REASON / DETAILS".bold()
    );
    println!("{}", "-----------------------------------------------------------------------------------------".dimmed());

    for entry in entries {
        let short_ts = if entry.timestamp.len() >= 19 {
            &entry.timestamp[11..19]
        } else {
            &entry.timestamp
        };

        let status_colored = match entry.status.as_str() {
            "BLOCKED" => entry.status.bold().red(),
            "USER_DENIED" => entry.status.bold().yellow(),
            "USER_APPROVED" => entry.status.bold().green(),
            "ALLOWED" => entry.status.cyan(),
            _ => entry.status.normal(),
        };

        let reason = entry.reason.unwrap_or_else(|| "-".to_string());
        let truncated_reason = if reason.len() > 30 {
            format!("{}...", &reason[..27])
        } else {
            reason
        };

        println!(
            "{:<20} {:<15} {:<20} {:<25} {}",
            short_ts.dimmed(),
            entry.server,
            entry.tool.bold(),
            status_colored,
            truncated_reason.dimmed()
        );
    }
    println!("{}", "=========================================================================================\n".dimmed());

    Ok(())
}
