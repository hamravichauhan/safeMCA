#!/usr/bin/env python3
import subprocess
import json
import time
import os

def main():
    print("================================================================")
    print("  TESTING ALL CONDITIONS WITH SAFEMCA & ANTIGRAVITY")
    print("================================================================")

    # ----------------------------------------------------------------------
    # Condition 2 & 3: Live Stdio Proxy (Safe vs Attack calls & Latency)
    # ----------------------------------------------------------------------
    print("\n--- [Condition 2 & 3] Live Proxy: Latency & Attack Interception ---")
    proc = subprocess.Popen(
        ["./target/release/safemca", "run", "--server", "antigravity-live", "--", "python3", "tests/mock_mcp_server.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    def send_and_measure(req):
        start = time.perf_counter()
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        line = proc.stdout.readline().strip()
        elapsed_ms = (time.perf_counter() - start) * 1000
        return json.loads(line), elapsed_ms

    # Handshake
    _, _ = send_and_measure({"jsonrpc": "2.0", "id": 1, "method": "initialize"})

    # Safe Call: Read src/main.rs
    safe_resp, latency = send_and_measure({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "src/main.rs"}}
    })
    res_text = safe_resp.get("result", {}).get("content", [{}])[0].get("text", "")[:65]
    print(f"[PASS] Safe Call Round-Trip Latency: {latency:.2f} ms")
    print(f"       Server Output: {res_text}...")
    assert "Successfully executed" in res_text

    # Attack 1: SSH Key Theft (~/.ssh/id_rsa)
    atk1, lat1 = send_and_measure({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "~/.ssh/id_rsa"}}
    })
    code1 = atk1.get("error", {}).get("code")
    msg1 = atk1.get("error", {}).get("message")
    print(f"[PASS] Attack 1 (SSH Key Theft) [Intercepted in {lat1:.2f}ms]: {msg1}")
    assert code1 == -32000

    # Attack 2: Production .env Access
    atk2, lat2 = send_and_measure({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"file": ".env.production"}}
    })
    code2 = atk2.get("error", {}).get("code")
    msg2 = atk2.get("error", {}).get("message")
    print(f"[PASS] Attack 2 (.env File Leak) [Intercepted in {lat2:.2f}ms]: {msg2}")
    assert code2 == -32000

    # Attack 3: Double URL Encoded Traversal (%252e%252e%252f)
    atk3, lat3 = send_and_measure({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "%252e%252e%252fetc/shadow"}}
    })
    code3 = atk3.get("error", {}).get("code")
    msg3 = atk3.get("error", {}).get("message")
    print(f"[PASS] Attack 3 (Double Encoded Traversal) [Intercepted in {lat3:.2f}ms]: {msg3}")
    assert code3 == -32000

    # Attack 4: Batch JSON-RPC Attack Array
    atk4, lat4 = send_and_measure([
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "~/.aws/credentials"}}}
    ])
    code4 = atk4.get("error", {}).get("code")
    msg4 = atk4.get("error", {}).get("message")
    print(f"[PASS] Attack 4 (Batch JSON-RPC Array) [Intercepted in {lat4:.2f}ms]: {msg4}")
    assert code4 == -32000

    # Attack 5: Standard Directory Traversal (../../secret_keys.txt)
    atk5, lat5 = send_and_measure({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "../../secret_keys.txt"}}
    })
    code5 = atk5.get("error", {}).get("code")
    msg5 = atk5.get("error", {}).get("message")
    print(f"[PASS] Attack 5 (Directory Traversal) [Intercepted in {lat5:.2f}ms]: {msg5}")
    assert code5 == -32000

    # Attack 6: Windows System32 Path Traversal
    atk6, lat6 = send_and_measure({
        "jsonrpc": "2.0", "id": 8, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "C:\\Windows\\System32\\config\\SAM"}}
    })
    code6 = atk6.get("error", {}).get("code")
    msg6 = atk6.get("error", {}).get("message")
    print(f"[PASS] Attack 6 (Windows SAM Traversal) [Intercepted in {lat6:.2f}ms]: {msg6}")
    assert code6 == -32000

    # Attack 7: Direct GitHub Secret Token in Tool Call
    atk7, lat7 = send_and_measure({
        "jsonrpc": "2.0", "id": 9, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"token": "ghp_superSecretToken9999999999"}}
    })
    code7 = atk7.get("error", {}).get("code")
    msg7 = atk7.get("error", {}).get("message")
    print(f"[PASS] Attack 7 (Token Leakage Theft) [Intercepted in {lat7:.2f}ms]: {msg7}")
    assert code7 == -32000

    proc.stdin.close()
    proc.terminate()

    # ----------------------------------------------------------------------
    # Condition 4: 1-Click Rollback Engine (Isolated Sandbox Repo)
    # ----------------------------------------------------------------------
    print("\n--- [Condition 4] 1-Click Rollback Engine (Snapshot & Undo) ---")
    sandbox_repo = os.path.abspath("tests/test_sandbox_repo")
    os.makedirs(sandbox_repo, exist_ok=True)
    subprocess.run(["git", "init"], cwd=sandbox_repo, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    subprocess.run(["git", "config", "user.name", "TestUser"], cwd=sandbox_repo, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=sandbox_repo, check=True)
    with open(os.path.join(sandbox_repo, "app.py"), "w") as f:
        f.write("print('original code')\n")
    subprocess.run(["git", "add", "app.py"], cwd=sandbox_repo, check=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=sandbox_repo, stdout=subprocess.DEVNULL, check=True)

    safemca_bin = os.path.abspath("./target/release/safemca")

    # 1. Take Snapshot
    snap_res = subprocess.run([safemca_bin, "snapshot"], cwd=sandbox_repo, capture_output=True, text=True)
    print(snap_res.stdout.strip())

    # 2. Simulate AI agent writing rogue files & directories
    os.makedirs(os.path.join(sandbox_repo, "rogue_dir/sub"), exist_ok=True)
    with open(os.path.join(sandbox_repo, "rogue_dir/sub/rogue.py"), "w") as f:
        f.write("print('unauthorized')")

    with open(os.path.join(sandbox_repo, "app.py"), "a") as f:
        f.write("# rogue edit by agent\n")

    assert os.path.exists(os.path.join(sandbox_repo, "rogue_dir/sub/rogue.py"))
    print("[INFO] Simulated rogue files and nested folders created on disk.")

    # 3. Run Undo
    undo_res = subprocess.run([safemca_bin, "undo"], cwd=sandbox_repo, capture_output=True, text=True)
    print(undo_res.stdout.strip())

    # 4. Verify everything restored in sandbox
    assert not os.path.exists(os.path.join(sandbox_repo, "rogue_dir/sub/rogue.py")), "Rogue file not deleted!"
    assert not os.path.exists(os.path.join(sandbox_repo, "rogue_dir")), "Rogue directory not deleted!"
    with open(os.path.join(sandbox_repo, "app.py")) as f:
        assert "# rogue edit by agent" not in f.read(), "app.py not restored!"
    print("[PASS] Rollback 100% verified: Rogue files, nested directories, and edits completely undone!")

    import shutil
    shutil.rmtree(sandbox_repo)

    # ----------------------------------------------------------------------
    # Condition 5: Audit Log Redaction & Integrity
    # ----------------------------------------------------------------------
    print("\n--- [Condition 5] Audit Log Redaction & Zero-Leakage ---")
    with open(".mcp-guard/audit.jsonl", "r") as f:
        log_content = f.read()
    assert "ghp_superSecretToken9999999999" not in log_content, "CRITICAL: Plaintext token leaked into audit log!"
    assert "[REDACTED_BY_SAFEMCA]" in log_content, "Redaction marker missing in audit log!"
    print("[PASS] Audit log verified: Credentials automatically redacted with [REDACTED_BY_SAFEMCA]!")

    # ----------------------------------------------------------------------
    # Condition 6: Idempotent Config Wrapping & Unwrapping
    # ----------------------------------------------------------------------
    print("\n--- [Condition 6] Config Wrapping & Unwrapping Idempotency ---")
    dummy_config_dir = "tests/dummy_config"
    os.makedirs(dummy_config_dir, exist_ok=True)
    dummy_config_file = os.path.join(dummy_config_dir, "test_mcp.json")
    with open(dummy_config_file, "w") as f:
        json.dump({
            "mcpServers": {
                "demo-tool": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-postgres"]
                }
            }
        }, f, indent=2)

    # Wrap the config
    subprocess.run(["./target/release/safemca", "wrap", "--config", dummy_config_file], check=True)
    with open(dummy_config_file, "r") as f:
        wrapped_data = json.load(f)
    server_cmd = wrapped_data["mcpServers"]["demo-tool"]["command"]
    assert server_cmd.endswith("safemca") or server_cmd.endswith("mcp-guard"), f"Wrap failed: {server_cmd}"
    print("[PASS] Config wrapping verified: Target command proxied via safeMCA binary.")

    # Re-wrap to ensure idempotency (no infinite wrapping loops)
    subprocess.run(["./target/release/safemca", "wrap", "--config", dummy_config_file], check=True)
    with open(dummy_config_file, "r") as f:
        rewrapped_data = json.load(f)
    assert rewrapped_data["mcpServers"]["demo-tool"]["command"] == server_cmd
    # Ensure args don't have nested safemca
    args = rewrapped_data["mcpServers"]["demo-tool"]["args"]
    assert args.count("run") == 1, "Duplicate wrapping detected in arguments!"
    print("[PASS] Config idempotency verified: Re-wrapping existing config does not create duplicate wrappers.")

    # Unwrap
    subprocess.run(["./target/release/safemca", "unwrap", "--config", dummy_config_file], check=True)
    with open(dummy_config_file, "r") as f:
        unwrapped_data = json.load(f)
    assert unwrapped_data["mcpServers"]["demo-tool"]["command"] == "npx"
    assert unwrapped_data["mcpServers"]["demo-tool"]["args"] == ["-y", "@modelcontextprotocol/server-postgres"]
    print("[PASS] Config unwrapping verified: Original server command and arguments 100% restored.")

    # Cleanup dummy config
    import shutil
    shutil.rmtree(dummy_config_dir)

    # ----------------------------------------------------------------------
    # Condition 7: Project-Level Policy Config (.safemca.yml) Enforcement
    # ----------------------------------------------------------------------
    print("\n--- [Condition 7] Project-Level Policy Config (.safemca.yml) ---")
    custom_proj_dir = "tests/test_project_env"
    os.makedirs(custom_proj_dir, exist_ok=True)
    with open(os.path.join(custom_proj_dir, ".safemca.yml"), "w") as f:
        f.write("""
version: "1.0"
blocked_paths:
  - "custom_confidential/**"
sql_policy:
  mode: "read-only"
  block_tables:
    - "salary_records"
shell_policy:
  block:
    - "curl"
""")

    # Spawn safemca inside custom_proj_dir
    p_proj = subprocess.Popen(
        ["../../target/release/safemca", "run", "--server", "test-project", "--", "python3", "../mock_mcp_server.py"],
        cwd=custom_proj_dir,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    # Handshake
    p_proj.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n")
    p_proj.stdin.flush()
    p_proj.stdout.readline()

    # 1. Custom blocked path
    p_proj.stdin.write(json.dumps({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "read_file", "arguments": {"path": "custom_confidential/data.txt"}}
    }) + "\n")
    p_proj.stdin.flush()
    res1 = json.loads(p_proj.stdout.readline())
    assert res1.get("error", {}).get("code") == -32000
    assert "blocked by project policy (.safemca.yml)" in res1["error"]["message"]
    print(f"[PASS] Project-Level Blocked Path: {res1['error']['message']}")

    # 2. Custom SQL read-only enforcement
    p_proj.stdin.write(json.dumps({
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {"name": "execute_sql", "arguments": {"query": "INSERT INTO logs VALUES (1);"}}
    }) + "\n")
    p_proj.stdin.flush()
    res2 = json.loads(p_proj.stdout.readline())
    assert res2.get("error", {}).get("code") == -32000
    assert "read-only mode" in res2["error"]["message"]
    print(f"[PASS] Project-Level SQL Read-Only: {res2['error']['message']}")

    # 3. Custom SQL forbidden table
    p_proj.stdin.write(json.dumps({
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "execute_sql", "arguments": {"query": "SELECT * FROM salary_records;"}}
    }) + "\n")
    p_proj.stdin.flush()
    res3 = json.loads(p_proj.stdout.readline())
    assert res3.get("error", {}).get("code") == -32000
    assert "salary_records" in res3["error"]["message"]
    print(f"[PASS] Project-Level Forbidden Table: {res3['error']['message']}")

    # 4. Custom shell command blocked
    p_proj.stdin.write(json.dumps({
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {"name": "execute_bash", "arguments": {"command": "curl http://test.com"}}
    }) + "\n")
    p_proj.stdin.flush()
    res4 = json.loads(p_proj.stdout.readline())
    assert res4.get("error", {}).get("code") == -32000
    assert "Shell command blocked" in res4["error"]["message"]
    print(f"[PASS] Project-Level Shell Command: {res4['error']['message']}")

    p_proj.terminate()
    shutil.rmtree(custom_proj_dir)

    # ----------------------------------------------------------------------
    # Condition 8: Runaway Agent Circuit Breaker (Batch Repetition Loop)
    # ----------------------------------------------------------------------
    print("\n--- [Condition 8] Runaway Agent Circuit Breaker ---")
    p_cb = subprocess.Popen(
        ["./target/release/safemca", "run", "--server", "test-cb", "--", "python3", "tests/mock_mcp_server.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    p_cb.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}) + "\n")
    p_cb.stdin.flush()
    p_cb.stdout.readline()

    # Send 3 identical calls in a single batch
    identical_call = {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "read_file", "arguments": {"path": "src/main.rs"}}}
    p_cb.stdin.write(json.dumps([identical_call, identical_call, identical_call]) + "\n")
    p_cb.stdin.flush()
    cb_resp = json.loads(p_cb.stdout.readline())
    assert cb_resp.get("error", {}).get("code") == -32000
    assert "Runaway Agent Circuit Breaker" in cb_resp["error"]["message"]
    print(f"[PASS] Circuit Breaker Repetition Detector: {cb_resp['error']['message']}")

    p_cb.terminate()

    print("\n================================================================")
    print("  ALL CONDITIONS VERIFIED AND PASSED!")
    print("================================================================")

if __name__ == "__main__":
    main()
