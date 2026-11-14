# safeMCA (MCP-Guard)

**The Airbag & Security Shield for AI Agents using the Model Context Protocol (MCP)**

[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)

---

## What is safeMCA?

**safeMCA** (also executable as `mcp-guard`) is an ultra-fast, sub-millisecond security proxy written in Rust that sits invisibly between your AI clients (**Claude Desktop, Cursor, Antigravity**) and your **MCP Servers** (Postgres, Filesystem, GitHub, Bash).

Without safeMCA, AI models have **unrestricted "God-Mode" access** to execute commands, modify files, and query databases. A single prompt injection or hallucination can drop your tables or leak your private credentials.

safeMCA provides:
1. **The Airbag (Human-in-the-Loop):** Prompts you before destructive actions run (e.g. `DROP TABLE`, `rm -rf`, file deletions).
2. **Deterministic Sandboxing:** Physically blocks AI agents from touching `~/.ssh`, `~/.aws`, `.env`, or escaping your project directory.
3. **1-Click Rollback:** Automatically captures shadow snapshots so you can undo agent-made file changes with `safemca undo`.
4. **10-Second Auto-Wrap:** Automatically finds and wraps your Claude Desktop or Cursor configuration with one command.
5. **Tamper-Proof Audit Trail:** High-speed append-only logs of every tool call and blocked attack.

---

## Quickstart

### 1. Installation

```bash
# Build from source
cargo build --release

# Move binary to your PATH
cp target/release/safemca /usr/local/bin/
```

### 2. Protect Claude Desktop or Cursor in 10 Seconds

```bash
safemca wrap
```

Output:
```text
[OK] Created backup at ~/Library/Application Support/Claude/claude_desktop_config.json.backup
  [PROTECTED] Protected server: 'filesystem'
  [PROTECTED] Protected server: 'postgres'

[OK] Successfully protected 2 server(s)
All tool calls from Claude/Cursor will now pass through safeMCA.
```

To turn off safeMCA at any time:
```bash
safemca unwrap
```

---

## Demonstration: What safeMCA Protects Against

### 1. Credential Theft & Prompt Injections
If an AI agent visits a malicious website or reads a rogue prompt instructing it to exfiltrate your private keys:
```json
{"method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "~/.ssh/id_rsa"}}}
```
**safeMCA Reaction:**
* Instantly blocked in `<0.1ms`.
* Returns JSON-RPC Error: `Blocked by safeMCA: Access to sensitive file, credentials, or private keys is prohibited.`
* The target server never receives the command.

### 2. Accidental Destruction & Dangerous Commands
If an AI agent attempts to run a destructive command (`rm -rf` or `DROP TABLE`):
* **Terminal Mode:** Prompts user directly on `/dev/tty`:
  ```text
  [safeMCA Security Intercept] ----------------------------------
  Server:    postgres
  Tool:      execute_sql
  Reason:    Destructive SQL query detected in tool 'execute_sql'
  Arguments: {"query": "DROP TABLE users;"}
  -----------------------------------------------------------------
  Allow this action? [y/N]:
  ```
* **macOS GUI Mode (Claude Desktop):** Pops a native AppleScript dialog with a 30-second safe timeout.

### 3. 1-Click Undo / Rollback
If an agent edits or deletes code in your workspace and you want to revert:
```bash
safemca undo
```
Output:
```text
[UNDO] Restoring workspace to snapshot a8b7c3...
[OK] Successfully rolled back all file changes made by the AI agent!
```

---

## CLI Reference

| Command | Description |
| :--- | :--- |
| `safemca wrap` | Automatically wraps Claude Desktop / Cursor servers |
| `safemca unwrap` | Restores original unwrapped configuration |
| `safemca run --server <name> -- <cmd> [args]` | Runs a target MCP server through the security proxy |
| `safemca snapshot` | Captures baseline workspace state before running agents |
| `safemca undo` | Reverts all file changes and purges rogue files/dirs created by agents |
| `safemca audit [--tail 20]` | Displays recent security audit logs (with redacted credentials) |
| `safemca test` | Runs self-check verifying that all attacks are blocked |

---

## Architecture

```text
Claude Desktop / Cursor
       |  (Stdio JSON-RPC)
       v
+----------------------------------------------+
|  safeMCA (Single 3.4MB Rust Binary)          |
|                                              |
|  1. Async Stream Engine (<0.2ms overhead)    |
|  2. Path & Secret Sandbox (Regex Blockers)   |
|  3. Interactive Prompter (/dev/tty & macOS)  |
|  4. Git Shadow Snapshot & Undo Engine        |
|  5. Append-Only Local Audit Log              |
+----------------------------------------------+
       |  (Sanitized JSON-RPC)
       v
Target MCP Server (Postgres, Filesystem, Bash)
```

---

## License
MIT License. Open source and free for developers and teams.
