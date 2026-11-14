use colored::Colorize;
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::process::Command;

pub struct HitlPrompter;

impl HitlPrompter {
    pub fn prompt(server: &str, tool: &str, reason: &str, arguments: &Value) -> bool {
        // Channel 1: Try direct /dev/tty (Terminal / Cursor / IDE Shell)
        if let Ok(tty_file) = OpenOptions::new().read(true).write(true).open("/dev/tty") {
            return Self::prompt_tty(tty_file, server, tool, reason, arguments);
        }

        // Channel 2: GUI Mode on macOS (Claude Desktop)
        if cfg!(target_os = "macos") {
            return Self::prompt_macos_dialog(server, tool, reason, arguments);
        }

        // Safe by default if no interactive channel is reachable
        eprintln!(
            "{}",
            format!(
                "[safeMCA] Denied tool call '{}' (no interactive terminal or GUI available).",
                tool
            )
            .red()
        );
        false
    }

    fn prompt_tty(
        mut tty_file: std::fs::File,
        server: &str,
        tool: &str,
        reason: &str,
        arguments: &Value,
    ) -> bool {
        let args_pretty = serde_json::to_string_pretty(arguments).unwrap_or_else(|_| arguments.to_string());
        let truncated_args = if args_pretty.len() > 300 {
            format!("{}...", &args_pretty[..300])
        } else {
            args_pretty
        };

        let banner = format!(
            "\n{}\n{} {}\n{}   {}\n{} {}\n{}  {}\n{}\n{} [y/N]: ",
            "🛡️  [safeMCA Security Intercept] ------------------------------".bold().yellow(),
            "Server:   ".bold(),
            server.cyan(),
            "Tool:     ".bold(),
            tool.green().bold(),
            "Reason:   ".bold(),
            reason.yellow(),
            "Arguments:".bold(),
            truncated_args.dimmed(),
            "-----------------------------------------------------------------".yellow(),
            "Allow this action?".bold().bright_white()
        );

        let _ = tty_file.write_all(banner.as_bytes());
        let _ = tty_file.flush();

        let mut reader = BufReader::new(tty_file);
        let mut line = String::new();
        if reader.read_line(&mut line).is_ok() {
            let answer = line.trim().to_lowercase();
            if answer == "y" || answer == "yes" {
                return true;
            }
        }

        false
    }

    fn escape_applescript(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace(['\r', '\n'], " ")
    }

    fn prompt_macos_dialog(server: &str, tool: &str, reason: &str, arguments: &Value) -> bool {
        let args_str = serde_json::to_string(arguments).unwrap_or_else(|_| "".to_string());
        let preview = if args_str.len() > 120 {
            format!("{}...", &args_str[..120])
        } else {
            args_str
        };

        let safe_server = Self::escape_applescript(server);
        let safe_tool = Self::escape_applescript(tool);
        let safe_reason = Self::escape_applescript(reason);
        let safe_preview = Self::escape_applescript(&preview);

        let script = format!(
            r#"button returned of (display dialog "🛡️ safeMCA Alert\n\nServer: {}\nTool: {}\nReason: {}\n\nArguments:\n{}\n\nDo you want to allow this action?" buttons {{"Deny", "Allow"}} default button "Deny" with icon caution giving up after 30)"#,
            safe_server, safe_tool, safe_reason, safe_preview
        );

        if let Ok(output) = Command::new("osascript").arg("-e").arg(&script).output() {
            let res = String::from_utf8_lossy(&output.stdout);
            if res.trim() == "Allow" {
                return true;
            }
        }

        false
    }
}
