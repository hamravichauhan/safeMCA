# safeMCA (MCP-Guard)

**The Airbag & Security Shield for AI Agents using the Model Context Protocol (MCP)**

[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)
[![safeMCA Protected](https://img.shields.io/badge/MCP-safeMCA_Protected-blue)](https://github.com/hamravichauhan/safeMCA)

---

## What is safeMCA?

**safeMCA** (also executable as `mcp-guard`) is an ultra-fast, sub-millisecond security proxy written in Rust that sits invisibly between your AI clients (**Claude Desktop, Cursor, Antigravity**) and your **MCP Servers** (Postgres, Filesystem, GitHub, Bash).

Without safeMCA, AI models have **unrestricted "God-Mode" access** to execute commands, modify files, and query databases. A single prompt injection or hallucination can drop your tables or leak your private credentials.

safeMCA provides:
1. **The Airbag (Human-in-the-Loop):** Prompts you before destructive actions run (e.g. `DROP TABLE`, `rm -rf`, file deletions).
2. **Deterministic Sandboxing:** Physically blocks AI agents from touching `~/.ssh`, `~/.aws`, `.env`, or escaping your project directory.
3. **Runaway Agent Circuit Breaker:** Stops infinite loops and rate limit runaway (3 identical calls or >30 calls/min).
4. **Project-Level Policies (`.safemca.yml`):** Commit security policies into git to enforce team-wide path, shell, and SQL boundaries.
5. **1-Click Rollback:** Automatically captures shadow snapshots so you can undo agent-made file changes with `safemca undo`.
6. **10-Second Auto-Wrap:** Automatically finds and wraps your Claude Desktop or Cursor configuration with one command.
7. **Tamper-Proof Audit Trail:** High-speed append-only logs of every tool call and blocked attack with automated secret redaction.

---

## Quickstart

### 1. Installation

Choose whichever method fits your setup:

**Option A: Zero Install with NPX (macOS, Windows, Linux)**
```bash
npx safemca wrap
```

**Option B: Cargo Install (Rust)**
```bash
cargo install safemca
```

**Option C: Pre-Built Standalone Binaries**
Download the single binary for your operating system from [GitHub Releases](https://github.com/hamravichauhan/safeMCA/releases/tag/v0.1.0):
* macOS Apple Silicon (`safemca-macos-arm64.tar.gz`)
* macOS Intel (`safemca-macos-x86_64.tar.gz`)
* Windows x64 (`safemca-windows-x86_64.tar.gz` with `safemca.exe`)
* Linux x64 (`safemca-linux-x86_64.tar.gz`)

**Option D: Build from Source**
```bash
git clone https://github.com/hamravichauhan/safeMCA.git
cd safeMCA
cargo build --release
cp target/release/safemca /usr/local/bin/
```

### 2. Protect Claude Desktop, Cursor, or Antigravity in 10 Seconds

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

## Enterprise & Team Security: `.safemca.yml`

Teams can commit a `.safemca.yml` file into their project root to enforce deterministic policies across all developers and AI agents:

```yaml
version: "1.0"

# Paths that agents are prohibited from reading or modifying
blocked_paths:
  - "infra/secrets/**"
  - "deploy/credentials.pem"
  - "billing/**"

# Database policy
sql_policy:
  mode: "read-only" # Hard blocks INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE
  block_tables:
    - "users"
    - "payroll"

# Terminal and execution command boundaries
shell_policy:
  allow:
    - "cargo test"
    - "npm test"
    - "git status"
  block:
    - "curl"
    - "wget"
    - "rm"
    - "git push"

# Circuit breaker thresholds
circuit_breaker:
  max_calls_per_minute: 30
  max_identical_consecutive_calls: 3
```

---

## Runaway Agent Circuit Breaker

Autonomous coding agents can get trapped in hallucination loops, hammering tools hundreds of times and wasting API tokens or modifying databases.

safeMCA includes a built-in circuit breaker:
1. **Repetition Loop Breaker:** If an agent calls the exact same tool with the exact same arguments 3 times consecutively, safeMCA trips the breaker and requires human confirmation before continuing.
2. **Rate Limiting:** Protects against runaway scripts by limiting tool invocations to 30 calls per minute by default (configurable via `.safemca.yml`).

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
