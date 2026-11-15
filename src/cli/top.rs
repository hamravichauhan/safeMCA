use crate::storage::telemetry::TelemetryCollector;
use colored::Colorize;
use std::env;

pub fn execute() -> anyhow::Result<()> {
    let current_dir = env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let stats = TelemetryCollector::compute_stats(&current_dir);

    println!("\n{}", "safeMCP Live Runtime Inspector & Telemetry".bold().cyan());
    println!("{}", "========================================================================".dimmed());

    let servers_display = if stats.active_servers.is_empty() {
        "None (No active sessions recorded)".dimmed().to_string()
    } else {
        stats.active_servers.join(", ").bold().green().to_string()
    };
    println!("{:<28} {}", "Active MCP Servers:".bold(), servers_display);
    println!("{:<28} {}", "Total Interceptions:".bold(), stats.total_calls.to_string().cyan().bold());
    println!("{:<28} {}", "Allowed Calls:".bold(), stats.allowed_calls.to_string().green());
    println!("{:<28} {}", "User Confirmed (HITL):".bold(), stats.user_approved_calls.to_string().yellow());
    println!("{:<28} {}", "User Denied:".bold(), stats.user_denied_calls.to_string().red());
    println!("{:<28} {}", "Hard Blocked Attacks:".bold(), stats.blocked_calls.to_string().red().bold());

    println!("\n{}", "Threat Defenses:".bold().yellow());
    println!("  • {:<26} {}", "Indirect Prompt Injections:".dimmed(), stats.prompt_injections_blocked.to_string().red().bold());
    println!("  • {:<26} {}", "Circuit Breaker Trips:".dimmed(), stats.circuit_breaker_trips.to_string().yellow().bold());

    println!("\n{}", "Context & Token Optimization:".bold().green());
    println!("  • {:<26} {}", "Airbag Truncations:".dimmed(), stats.airbag_truncations.to_string().cyan());
    let airbag_kb = (stats.bytes_saved_airbag as f64) / 1024.0;
    let airbag_tokens = stats.bytes_saved_airbag / 4;
    println!("  • {:<26} {:.1} KB (~{} tokens)", "Bytes Saved (Airbag):".dimmed(), airbag_kb, airbag_tokens);

    let schema_kb = (stats.bytes_saved_minifier as f64) / 1024.0;
    let schema_tokens = stats.bytes_saved_minifier / 4;
    println!("  • {:<26} {}", "Schema Minifications:".dimmed(), stats.schema_minifications.to_string().cyan());
    println!("  • {:<26} {:.1} KB (~{} tokens)", "Bytes Saved (Schemas):".dimmed(), schema_kb, schema_tokens);

    let total_tokens_saved = airbag_tokens + schema_tokens;
    println!("\n{:<28} {}", "Total Working Tokens Saved:".bold(), format!("~{} tokens", total_tokens_saved).bold().green());
    println!("{}", "========================================================================\n".dimmed());

    Ok(())
}
