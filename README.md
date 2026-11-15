# safeMCP (MCP-Guard)

**The Airbag & Security Shield for AI Agents using the Model Context Protocol (MCP)**

[![Crates.io](https://img.shields.io/crates/v/safemcp.svg)](https://crates.io/crates/safemcp)
[![Built with Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-Compatible-green.svg)](https://modelcontextprotocol.io/)
[![safeMCP Protected](https://img.shields.io/badge/MCP-safeMCP_Protected-blue)](https://github.com/hamravichauhan/safeMCP)

---

## What is safeMCP?

**safeMCP** (also executable as `mcp-guard`) is an ultra-fast, sub-millisecond security proxy written in Rust that sits invisibly between your AI clients (**Claude Desktop, Cursor, Antigravity**) and your **MCP Servers** (Postgres, Filesystem, GitHub, Bash).

Without safeMCP, AI models have **unrestricted "God-Mode" access** to execute commands, modify files, and query databases. A single prompt injection or hallucination can drop your tables or leak your private credentials.

safeMCP provides:
1. **The Airbag (Human-in-the-Loop):** Prompts you before destructive actions run (e.g. `DROP TABLE`, `rm -rf`, file deletions).
2. **Deterministic Sandboxing:** Physically blocks AI agents from touching `~/.ssh`, `~/.aws`, `.env`, or escaping your project directory.
3. **Bidirectional Response Guard:** Intercepts indirect prompt injections, hidden unicode obfuscations, and exfiltration beacons in tool outputs.
4. **Response Size Airbag:** Automatically truncates and caches oversized outputs (32KB+) to `.safemcp/cache/` to prevent LLM context exhaustion.
5. **Stdio Stream Sanitizer:** Catches stray `console.log()` or `print()` outputs from child servers, diverting them to stderr to prevent silent JSON-RPC connection crashes.
6. **Schema Minifier & Tool Router:** Compresses `tools/list` JSON schemas by 40-60% to eliminate the 50,000 token tax on every prompt.
7. **Zero-Plaintext Secret Vault:** Replaces hardcoded keys in config files with `{{safemcp:keychain/...}}` OS keychain integration.
8. **Runaway Agent Circuit Breaker:** Stops infinite loops and rate limit runaway (3 identical calls or >30 calls/min).
9. **Project-Level Policies (`.safemcp.yml`):** Commit security policies into git to enforce team-wide path, shell, and SQL boundaries.
10. **1-Click Rollback:** Automatically captures shadow snapshots so you can undo agent-made file changes with `safemcp undo`.
11. **Live Runtime Inspector (`safemcp top`):** Real-time terminal dashboard tracking active servers, token savings, latency, and threats.
12. **Tamper-Evident Hash-Chained Audit Trail:** Cryptographic SHA-256 ledger with automated salted credential redaction and `safemcp audit --verify`.

---

## Quickstart

### 1. Installation

Choose whichever method fits your setup:

**Option A: Cargo Install (Rust)**
```bash
cargo install safemcp
```

**Option B: Zero Install with NPX (macOS, Windows, Linux)**
```bash
npx safe-mcp wrap
```

**Option C: Homebrew (macOS / Linux)**
```bash
brew install hamravichauhan/safemcp/safemcp
```

**Option D: Pre-Built Standalone Binaries**
Download the single binary for your operating system from [GitHub Releases](https://github.com/hamravichauhan/safeMCP/releases):
* macOS Apple Silicon (`safemcp-macos-arm64.tar.gz`)
* macOS Intel (`safemcp-macos-x86_64.tar.gz`)
* Windows x64 (`safemcp-windows-x86_64.tar.gz` with `safemcp.exe`)
* Linux x64 (`safemcp-linux-x86_64.tar.gz`)

**Option E: Build from Source**
```bash
git clone https://github.com/hamravichauhan/safeMCP.git
cd safeMCP
cargo build --release
cp target/release/safemcp /usr/local/bin/
```

### 2. Protect Claude Desktop, Cursor, or Antigravity in 10 Seconds

```bash
safemcp wrap
```

Output:
```text
[OK] Created backup at ~/Library/Application Support/Claude/claude_desktop_config.json.backup
  [PROTECTED] Protected server: 'filesystem'
  [PROTECTED] Protected server: 'postgres'

[OK] Successfully protected 2 server(s)
All tool calls from Claude/Cursor will now pass through safeMCP.
```

To turn off safeMCP at any time:
```bash
safemcp unwrap
```

---

## Demonstration: What safeMCP Protects Against

### 1. Credential Theft & Prompt Injections
If an AI agent visits a malicious website or reads a rogue prompt instructing it to exfiltrate your private keys:
```json
{"method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "~/.ssh/id_rsa"}}}
```
**safeMCP Reaction:**
* Instantly blocked in `<0.2ms`.
* Returns JSON-RPC Error: `Blocked by safeMCP: Access to sensitive file, credentials, or private keys is prohibited.`
* The target server never receives the command.

### 2. Accidental Destruction & Dangerous Commands
If an AI agent attempts to run a destructive command (`rm -rf` or `DROP TABLE`):
* **Terminal Mode:** Prompts user directly on `/dev/tty`:
  ```text
  [safeMCP Security Intercept] ----------------------------------
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
safemcp undo
```
Output:
```text
[UNDO] Restoring workspace to snapshot a8b7c3...
[OK] Successfully rolled back all file changes made by the AI agent!
```

---

## Enterprise & Team Security: `.safemcp.yml`

Teams can commit a `.safemcp.yml` file into their project root to enforce deterministic policies across all developers and AI agents:

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

safeMCP includes a built-in circuit breaker:
1. **Repetition Loop Breaker:** If an agent calls the exact same tool with the exact same arguments 3 times consecutively, safeMCP trips the breaker and requires human confirmation before continuing.
2. **Rate Limiting:** Protects against runaway scripts by limiting tool invocations to 30 calls per minute by default (configurable via `.safemcp.yml`).

---

## CLI Reference

| Command | Description |
| :--- | :--- |
| `safemcp wrap` | Automatically wraps Claude Desktop / Cursor servers |
| `safemcp unwrap` | Restores original unwrapped configuration |
| `safemcp run --server <name> -- <cmd> [args]` | Runs a target MCP server through the security proxy |
| `safemcp top` | Live terminal inspector displaying telemetry and token savings |
| `safemcp snapshot` | Captures baseline workspace state before running agents |
| `safemcp undo` | Reverts all file changes and purges rogue files/dirs created by agents |
| `safemcp audit [--tail 20]` | Displays recent security audit logs (with redacted credentials) |
| `safemcp audit --verify` | Cryptographically verifies SHA-256 hash-chain integrity of audit ledger |
| `safemcp test` | Runs self-check verifying that all attacks and injections are blocked |

---

## Architecture

```text
Claude Desktop / Cursor
       |  (Stdio JSON-RPC)
       v
+----------------------------------------------+
|  safeMCP (Single 3.9MB Rust Binary)          |
|                                              |
|  1. Async Stream Engine (<0.2ms overhead)    |
|  2. Stdio Stream Sanitizer (No broken pipes) |
|  3. Response Size Airbag & Local Cache       |
|  4. Bidirectional Response Guard             |
|  5. Path & Secret Sandbox (Regex Blockers)   |
|  6. Interactive Prompter (/dev/tty & GUI)    |
|  7. Git Shadow Snapshot & Undo Engine        |
|  8. Append-Only Cryptographic Audit Log      |
+----------------------------------------------+
       |  (Sanitized JSON-RPC)
       v
Target MCP Server (Postgres, Filesystem, Bash)
```

---

## License
MIT License. Open source and free for developers and teams.
