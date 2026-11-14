use anyhow::{Context, Result};
use colored::Colorize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

pub fn find_default_configs() -> Vec<PathBuf> {
    let mut configs = Vec::new();

    if let Some(home) = dirs::home_dir() {
        // 1. Claude Desktop macOS
        let claude_mac = home.join("Library/Application Support/Claude/claude_desktop_config.json");
        if claude_mac.exists() {
            configs.push(claude_mac);
        }

        // 2. Claude Desktop Windows / Linux
        let claude_roaming = home.join("AppData/Roaming/Claude/claude_desktop_config.json");
        if claude_roaming.exists() {
            configs.push(claude_roaming);
        }

        // 3. Cursor MCP Global
        let cursor_global = home.join(".cursor/mcp.json");
        if cursor_global.exists() {
            configs.push(cursor_global);
        }

        // 4. Google Antigravity / Gemini CLI MCP Config
        let antigravity_mcp = home.join(".gemini/config/mcp_config.json");
        if antigravity_mcp.exists() {
            configs.push(antigravity_mcp);
        }
    }

    // 4. Local workspace .cursor/mcp.json
    let local_cursor = PathBuf::from(".cursor/mcp.json");
    if local_cursor.exists() {
        configs.push(local_cursor);
    }

    configs
}

pub fn execute(custom_config: Option<PathBuf>) -> Result<()> {
    let targets = if let Some(path) = custom_config {
        vec![path]
    } else {
        let found = find_default_configs();
        if found.is_empty() {
            println!("{}", "No Claude Desktop or Cursor MCP configs found automatically.".yellow());
            println!("You can specify one manually with: {}", "mcp-guard wrap --config <path/to/config.json>".cyan());
            return Ok(());
        }
        found
    };

    for config_path in targets {
        wrap_config(&config_path)?;
    }

    Ok(())
}

fn wrap_config(path: &Path) -> Result<()> {
    let content = fs::read_to_string(path).with_context(|| format!("Failed to read {:?}", path))?;
    let mut root: Value = if content.trim().is_empty() {
        serde_json::json!({ "mcpServers": {} })
    } else {
        serde_json::from_str(&content).with_context(|| format!("Invalid JSON in {:?}", path))?
    };

    let mcp_servers = match root.get_mut("mcpServers").and_then(|s| s.as_object_mut()) {
        Some(s) => s,
        None => {
            println!("{} No 'mcpServers' object found in {:?}", "[WARN]".yellow(), path);
            return Ok(());
        }
    };

    // Create backup file first
    let backup_path = path.with_extension("json.backup");
    if !backup_path.exists() {
        fs::write(&backup_path, &content).with_context(|| format!("Failed to create backup at {:?}", backup_path))?;
        println!("{} Created backup at {:?}", "[OK]".green(), backup_path);
    }

    let mut wrapped_count = 0;

    for (server_name, server_val) in mcp_servers.iter_mut() {
        if let Some(server_obj) = server_val.as_object_mut() {
            let current_cmd = server_obj.get("command").and_then(|c| c.as_str()).unwrap_or("");
            if current_cmd == "mcp-guard" || current_cmd == "safemca" || current_cmd.ends_with("/mcp-guard") || current_cmd.ends_with("/safemca") {
                println!("  • Server '{}' is already wrapped", server_name.cyan());
                continue;
            }

            let original_cmd = current_cmd.to_string();
            let original_args: Vec<String> = server_obj
                .get("args")
                .and_then(|a| a.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            let mut new_args = vec![
                "run".to_string(),
                "--server".to_string(),
                server_name.clone(),
                "--".to_string(),
                original_cmd,
            ];
            new_args.extend(original_args);

            server_obj.insert("command".to_string(), Value::String("mcp-guard".to_string()));
            server_obj.insert("args".to_string(), serde_json::to_value(new_args)?);

            println!("  {} Protected server: '{}'", "[PROTECTED]".green(), server_name.bold().green());
            wrapped_count += 1;
        }
    }

    if wrapped_count > 0 {
        let updated_content = serde_json::to_string_pretty(&root)?;
        fs::write(path, updated_content)?;
        println!(
            "\n{} Successfully protected {} server(s) in {:?}",
            "[OK]".bold().green(),
            wrapped_count,
            path
        );
        println!("All tool calls from Claude/Cursor will now pass through MCP-Guard.");
    } else {
        println!("No changes needed in {:?}", path);
    }

    Ok(())
}
