use crate::core::protocol::ParsedMessage;
use crate::guard::hitl::HitlPrompter;
use crate::guard::policy::{GuardPolicy, PolicyDecision};
use crate::guard::rollback::RollbackEngine;
use crate::storage::audit::AuditLogger;
use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;

pub struct StdioProxy {
    server_name: String,
}

impl StdioProxy {
    pub fn new(server_name: &str) -> Self {
        Self {
            server_name: server_name.to_string(),
        }
    }

    pub async fn run(&self, command: &str, args: &[String]) -> Result<()> {
        let mut cmd = Command::new(command);
        cmd.args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true); // Ensure child process does not become an orphan if proxy drops

        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn child MCP server: '{}'", command))?;

        let mut child_stdin = child
            .stdin
            .take()
            .context("Failed to open child stdin pipe")?;
        let child_stdout = child
            .stdout
            .take()
            .context("Failed to open child stdout pipe")?;

        let mut client_stdin_reader = BufReader::new(tokio::io::stdin()).lines();
        let mut client_stdout = tokio::io::stdout();

        let mut server_stdout_reader = BufReader::new(child_stdout).lines();

        let server_name = self.server_name.clone();
        let policy = GuardPolicy::new();
        let audit = AuditLogger::new(&server_name);

        // Loop 1: Client -> Server (Interception & Guard)
        let client_to_server = async move {
            while let Ok(Some(line)) = client_stdin_reader.next_line().await {
                let parsed = ParsedMessage::parse(&line);

                match parsed {
                    ParsedMessage::ToolCall {
                        id,
                        tool_name,
                        arguments,
                        ..
                    } => {
                        let decision = policy.evaluate(&tool_name, &arguments);

                        match decision {
                            PolicyDecision::Block { reason } => {
                                audit.log(&server_name, &tool_name, &arguments, "BLOCKED", Some(&reason));

                                // Only reply if this was a request with an id (JSON-RPC spec: do not reply to notifications)
                                if !id.is_null() {
                                    let err_resp = ParsedMessage::make_error_response(
                                        &id,
                                        -32000,
                                        &format!("Blocked by MCP-Guard: {}", reason),
                                    );
                                    if client_stdout.write_all(err_resp.as_bytes()).await.is_err() {
                                        break;
                                    }
                                    let _ = client_stdout.flush().await;
                                }
                            }

                            PolicyDecision::RequireApproval { reason } => {
                                let approved = HitlPrompter::prompt(&server_name, &tool_name, &reason, &arguments);

                                if approved {
                                    audit.log(&server_name, &tool_name, &arguments, "USER_APPROVED", Some(&reason));
                                    let _ = RollbackEngine::take_snapshot();

                                    let mut line_nl = line;
                                    line_nl.push('\n');
                                    if child_stdin.write_all(line_nl.as_bytes()).await.is_err() {
                                        break;
                                    }
                                    let _ = child_stdin.flush().await;
                                } else {
                                    audit.log(&server_name, &tool_name, &arguments, "USER_DENIED", Some(&reason));

                                    if !id.is_null() {
                                        let err_resp = ParsedMessage::make_error_response(
                                            &id,
                                            -32000,
                                            "Blocked by MCP-Guard: Denied by user.",
                                        );
                                        if client_stdout.write_all(err_resp.as_bytes()).await.is_err() {
                                            break;
                                        }
                                        let _ = client_stdout.flush().await;
                                    }
                                }
                            }

                            PolicyDecision::Allow => {
                                audit.log(&server_name, &tool_name, &arguments, "ALLOWED", None);

                                let mut line_nl = line;
                                line_nl.push('\n');
                                if child_stdin.write_all(line_nl.as_bytes()).await.is_err() {
                                    break;
                                }
                                let _ = child_stdin.flush().await;
                            }
                        }
                    }

                    _ => {
                        // Non-tool messages (e.g. initialize, list_tools, responses) stream through
                        let mut line_nl = line;
                        line_nl.push('\n');
                        if child_stdin.write_all(line_nl.as_bytes()).await.is_err() {
                            break;
                        }
                        let _ = child_stdin.flush().await;
                    }
                }
            }
        };

        // Loop 2: Server -> Client (Response forwarding)
        let server_to_client = async move {
            let mut out = tokio::io::stdout();
            while let Ok(Some(line)) = server_stdout_reader.next_line().await {
                let mut line_nl = line;
                line_nl.push('\n');
                if out.write_all(line_nl.as_bytes()).await.is_err() {
                    break;
                }
                let _ = out.flush().await;
            }
        };

        // Run both streams concurrently until one terminates
        tokio::select! {
            _ = client_to_server => {},
            _ = server_to_client => {},
        }

        let _ = child.wait().await;
        Ok(())
    }
}
