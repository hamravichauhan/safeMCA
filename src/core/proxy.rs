use crate::core::protocol::ParsedMessage;
use crate::guard::circuit_breaker::CircuitBreaker;
use crate::guard::config::ProjectConfig;
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
        let mut server_stdout_reader = BufReader::new(child_stdout).lines();

        let server_name = self.server_name.clone();
        let current_dir = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let project_config = ProjectConfig::load_or_default(&current_dir);
        let mut circuit_breaker = CircuitBreaker::new(project_config.circuit_breaker.as_ref());
        let policy = GuardPolicy::with_config(project_config);
        let audit = AuditLogger::new(&server_name);

        // Loop 1: Client -> Server (Interception & Guard)
        let client_to_server = async move {
            let mut client_stdout = tokio::io::stdout();

            while let Ok(Some(line)) = client_stdin_reader.next_line().await {
                let parsed = ParsedMessage::parse(&line);

                match parsed {
                    ParsedMessage::ToolCall {
                        id,
                        tool_name,
                        arguments,
                        ..
                    } => {
                        // 1. Runaway Agent Circuit Breaker Check (Rate Limiter & Repetition Loop)
                        if let Err(trip) = circuit_breaker.check_and_record(&tool_name, &arguments) {
                            let trip_msg = trip.message();
                            audit.log(&server_name, &tool_name, &arguments, "CIRCUIT_BREAKER_TRIPPED", Some(&trip_msg));

                            let approved = HitlPrompter::prompt(&server_name, &tool_name, &trip_msg, &arguments);
                            if !approved {
                                audit.log(&server_name, &tool_name, &arguments, "USER_DENIED", Some(&trip_msg));
                                if !id.is_null() {
                                    let err_resp = ParsedMessage::make_error_response(
                                        &id,
                                        -32000,
                                        &format!("Blocked by safeMCA: {}", trip_msg),
                                    );
                                    if client_stdout.write_all(err_resp.as_bytes()).await.is_err() {
                                        break;
                                    }
                                    let _ = client_stdout.flush().await;
                                }
                                continue;
                            }
                            circuit_breaker.reset_consecutive();
                        }

                        // 2. Policy Evaluation (Deterministic Sandbox, Custom Policies & HITL)
                        let decision = policy.evaluate(&tool_name, &arguments);

                        match decision {
                            PolicyDecision::Block { reason } => {
                                audit.log(&server_name, &tool_name, &arguments, "BLOCKED", Some(&reason));

                                if !id.is_null() {
                                    let err_resp = ParsedMessage::make_error_response(
                                        &id,
                                        -32000,
                                        &format!("Blocked by safeMCA: {}", reason),
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
                                            "Blocked by safeMCA: Denied by user.",
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

                    ParsedMessage::Batch(items) => {
                        // Inspect all messages in the batch
                        let mut blocked_reason = None;
                        let mut require_approval_item = None;
                        let mut first_id = None;

                        for item in &items {
                            if let ParsedMessage::ToolCall { id, tool_name, arguments, .. } = item {
                                if first_id.is_none() {
                                    first_id = Some(id.clone());
                                }

                                // Circuit breaker check on batch item
                                if let Err(trip) = circuit_breaker.check_and_record(tool_name, arguments) {
                                    blocked_reason = Some((id.clone(), tool_name.clone(), arguments.clone(), trip.message()));
                                    break;
                                }

                                match policy.evaluate(tool_name, arguments) {
                                    PolicyDecision::Block { reason } => {
                                        blocked_reason = Some((id.clone(), tool_name.clone(), arguments.clone(), reason));
                                        break;
                                    }
                                    PolicyDecision::RequireApproval { reason } => {
                                        if require_approval_item.is_none() {
                                            require_approval_item = Some((id.clone(), tool_name.clone(), arguments.clone(), reason));
                                        }
                                    }
                                    PolicyDecision::Allow => {}
                                }
                            }
                        }

                        if let Some((id, tool_name, args, reason)) = blocked_reason {
                            audit.log(&server_name, &tool_name, &args, "BLOCKED", Some(&reason));
                            let err_resp = ParsedMessage::make_error_response(
                                &id,
                                -32000,
                                &format!("Blocked by safeMCA: Batch call contained blocked tool '{}': {}", tool_name, reason),
                            );
                            if client_stdout.write_all(err_resp.as_bytes()).await.is_err() {
                                break;
                            }
                            let _ = client_stdout.flush().await;
                        } else if let Some((id, tool_name, args, reason)) = require_approval_item {
                            let approved = HitlPrompter::prompt(&server_name, &tool_name, &reason, &args);
                            if approved {
                                audit.log(&server_name, &tool_name, &args, "USER_APPROVED", Some(&reason));
                                let _ = RollbackEngine::take_snapshot();

                                let mut line_nl = line;
                                line_nl.push('\n');
                                if child_stdin.write_all(line_nl.as_bytes()).await.is_err() {
                                    break;
                                }
                                let _ = child_stdin.flush().await;
                            } else {
                                audit.log(&server_name, &tool_name, &args, "USER_DENIED", Some(&reason));
                                let err_resp = ParsedMessage::make_error_response(
                                    &id,
                                    -32000,
                                    "Blocked by safeMCA: Denied by user.",
                                );
                                if client_stdout.write_all(err_resp.as_bytes()).await.is_err() {
                                    break;
                                }
                                let _ = client_stdout.flush().await;
                            }
                        } else {
                            // All items in batch allowed
                            let mut line_nl = line;
                            line_nl.push('\n');
                            if child_stdin.write_all(line_nl.as_bytes()).await.is_err() {
                                break;
                            }
                            let _ = child_stdin.flush().await;
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
