use crate::cli::wrap::find_default_configs;
use anyhow::{Context, Result};
use colored::Colorize;
use std::fs;
use std::path::{Path, PathBuf};

pub fn execute(custom_config: Option<PathBuf>) -> Result<()> {
    let targets = if let Some(path) = custom_config {
        vec![path]
    } else {
        let found = find_default_configs();
        if found.is_empty() {
            println!("{}", "No Claude Desktop or Cursor MCP configs found automatically.".yellow());
            return Ok(());
        }
        found
    };

    for config_path in targets {
        unwrap_config(&config_path)?;
    }

    Ok(())
}

fn unwrap_config(path: &Path) -> Result<()> {
    let backup_path = path.with_extension("json.backup");
    if !backup_path.exists() {
        println!("{} No backup found for {:?}", "⚠".yellow(), path);
        return Ok(());
    }

    let backup_content = fs::read_to_string(&backup_path)
        .with_context(|| format!("Failed to read backup from {:?}", backup_path))?;

    fs::write(path, backup_content).with_context(|| format!("Failed to restore config to {:?}", path))?;
    let _ = fs::remove_file(&backup_path);

    println!(
        "{} Restored original configuration for {:?}",
        "✓".bold().green(),
        path
    );

    Ok(())
}
