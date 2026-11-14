use crate::core::proxy::StdioProxy;
use anyhow::{bail, Result};

pub async fn execute(server: String, command: Vec<String>) -> Result<()> {
    if command.is_empty() {
        bail!("No command specified. Usage: mcp-guard run --server <name> -- <command> [args...]");
    }

    let cmd = &command[0];
    let args = &command[1..];

    let proxy = StdioProxy::new(&server);
    proxy.run(cmd, args).await
}
