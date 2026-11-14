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
    # Condition 4: 1-Click Rollback Engine
    # ----------------------------------------------------------------------
    print("\n--- [Condition 4] 1-Click Rollback Engine (Snapshot & Undo) ---")
    # 1. Take Snapshot
    snap_res = subprocess.run(["./target/release/safemca", "snapshot"], capture_output=True, text=True)
    print(snap_res.stdout.strip())

    # 2. Simulate AI agent writing rogue files & directories
    os.makedirs("antigravity_rogue_dir/sub", exist_ok=True)
    with open("antigravity_rogue_dir/sub/rogue_code.py", "w") as f:
        f.write("print('unauthorized agent script')")

    with open("README.md", "a") as f:
        f.write("\n<!-- rogue edit by agent -->\n")

    assert os.path.exists("antigravity_rogue_dir/sub/rogue_code.py")
    print("[INFO] Simulated rogue files and nested folders created on disk.")

    # 3. Run Undo
    undo_res = subprocess.run(["./target/release/safemca", "undo"], capture_output=True, text=True)
    print(undo_res.stdout.strip())

    # 4. Verify everything restored
    assert not os.path.exists("antigravity_rogue_dir/sub/rogue_code.py"), "Rogue file not deleted!"
    assert not os.path.exists("antigravity_rogue_dir"), "Rogue directory not deleted!"
    with open("README.md") as f:
        assert "<!-- rogue edit by agent -->" not in f.read(), "README not restored!"
    print("[PASS] Rollback 100% verified: Rogue files, nested directories, and edits completely undone!")

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

    print("\n================================================================")
    print("  ALL CONDITIONS VERIFIED AND PASSED!")
    print("================================================================")

if __name__ == "__main__":
    main()
