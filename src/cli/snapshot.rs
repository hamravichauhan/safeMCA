use crate::guard::rollback::RollbackEngine;
use anyhow::Result;
use colored::Colorize;

pub fn execute() -> Result<()> {
    match RollbackEngine::take_snapshot()? {
        Some(sha) => {
            println!(
                "{} Workspace snapshot captured ({})!\nYou can revert all changes anytime with '{}'.",
                "✓".bold().green(),
                sha.yellow(),
                "safemca undo".cyan()
            );
        }
        None => {
            println!("{}", "Workspace is not inside a git repository or git is unavailable.".yellow());
        }
    }
    Ok(())
}
