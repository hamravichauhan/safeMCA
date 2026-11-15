use anyhow::{Context, Result};
use colored::Colorize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
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

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(Self::state_dir(), fs::Permissions::from_mode(0o700));
        }

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

        println!("{} Restoring workspace to snapshot {}...", "[UNDO]".cyan(), sha.yellow());

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

        // 2. Remove any rogue untracked files or directories created by the agent
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
                    if current_file.starts_with(".mcp-guard")
                        || current_file.starts_with(".safemcp")
                        || current_file.starts_with(".safemca")
                    {
                        continue;
                    }
                    if !baseline_files.contains(current_file) {
                        let path = Path::new(current_file);
                        if path.is_dir() {
                            println!("  {} Removed rogue directory: {}", "[REMOVED]".yellow(), current_file.red());
                            let _ = fs::remove_dir_all(path);
                        } else if path.exists() {
                            println!("  {} Removed rogue file created by agent: {}", "[REMOVED]".yellow(), current_file.red());
                            let _ = fs::remove_file(path);

                            // Recursively clean up empty parent directories left by rogue agent files
                            let mut curr = path.parent();
                            while let Some(parent) = curr {
                                if parent == Path::new("") || parent == Path::new(".") {
                                    break;
                                }
                                if fs::remove_dir(parent).is_err() {
                                    break; // Stop when directory is not empty
                                }
                                curr = parent.parent();
                            }
                        }
                    }
                }
            }
            let _ = fs::remove_file(untracked_record);
        }

        if restored_tracked {
            println!(
                "{} {}",
                "[OK]".bold().green(),
                "Successfully rolled back all file changes made by the AI agent!".bold().green()
            );
            let _ = fs::remove_file(snap_file);
        } else {
            eprintln!("{}", "Failed to restore git snapshot.".red());
        }

        Ok(())
    }
}
