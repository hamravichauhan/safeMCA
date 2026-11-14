use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

pub struct RollbackEngine;

impl RollbackEngine {
    fn state_dir() -> PathBuf {
        PathBuf::from(".mcp-guard")
    }

    fn snapshot_file() -> PathBuf {
        Self::state_dir().join("last_snapshot_sha")
    }

    fn untracked_file() -> PathBuf {
        Self::state_dir().join("baseline_untracked.txt")
    }

    pub fn take_snapshot() -> Result<Option<String>> {
        // Verify we are inside a git repository
        let is_git = Command::new("git")
            .args(["rev-parse", "--is-inside-work-tree"])
            .output();

        if is_git.is_err() || !is_git.unwrap().status.success() {
            return Ok(None);
        }

        let _ = fs::create_dir_all(Self::state_dir());

        // Record baseline untracked files
        if let Ok(untracked_out) = Command::new("git")
            .args(["ls-files", "--others", "--exclude-standard"])
            .output()
        {
            let _ = fs::write(Self::untracked_file(), &untracked_out.stdout);
        }

        // git stash create creates a commit object of current working tree without modifying index
        let output = Command::new("git")
            .args(["stash", "create"])
            .output()
            .context("Failed to run git stash create")?;

        let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !sha.is_empty() {
            let _ = fs::write(Self::snapshot_file(), &sha);
            return Ok(Some(sha));
        }

        // If working tree is clean, capture the current HEAD SHA
        let head_output = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output();

        if let Ok(head_out) = head_output {
            let head_sha = String::from_utf8_lossy(&head_out.stdout).trim().to_string();
            if !head_sha.is_empty() {
                let _ = fs::write(Self::snapshot_file(), &head_sha);
                return Ok(Some(head_sha));
            }
        }

        Ok(None)
    }

    pub fn undo() -> Result<()> {
        let snap_file = Self::snapshot_file();
        if !snap_file.exists() {
            println!("{}", "No snapshot found to undo. Workspace is already at baseline.".yellow());
            return Ok(());
        }

        let sha = fs::read_to_string(&snap_file)?.trim().to_string();
        if sha.is_empty() {
            println!("{}", "Snapshot record was empty.".yellow());
            return Ok(());
        }

        println!("{} Restoring workspace to snapshot {}...", "⏪".cyan(), sha.yellow());

        // 1. Restore tracked working tree from snapshot commit
        let status = Command::new("git")
            .args(["restore", "--source", &sha, "--staged", "--worktree", "."])
            .status();

        let restored_tracked = match status {
            Ok(s) if s.success() => true,
            _ => {
                // Fallback for older git versions
                Command::new("git")
                    .args(["checkout", &sha, "--", "."])
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
            }
        };

        // 2. Remove any rogue untracked files created by the agent
        let untracked_record = Self::untracked_file();
        if untracked_record.exists() {
            let baseline_content = fs::read_to_string(&untracked_record).unwrap_or_default();
            let baseline_files: HashSet<String> = baseline_content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect();

            if let Ok(current_out) = Command::new("git")
                .args(["ls-files", "--others", "--exclude-standard"])
                .output()
            {
                let current_content = String::from_utf8_lossy(&current_out.stdout);
                for current_file in current_content.lines().map(|l| l.trim()).filter(|l| !l.is_empty()) {
                    if !baseline_files.contains(current_file) {
                        println!("  {} Removed rogue file created by agent: {}", "🗑️".yellow(), current_file.red());
                        let _ = fs::remove_file(current_file);
                    }
                }
            }
            let _ = fs::remove_file(untracked_record);
        }

        if restored_tracked {
            println!(
                "{} {}",
                "✓".bold().green(),
                "Successfully rolled back all file changes made by the AI agent!".bold().green()
            );
            let _ = fs::remove_file(snap_file);
        } else {
            eprintln!("{}", "Failed to restore git snapshot.".red());
        }

        Ok(())
    }
}
