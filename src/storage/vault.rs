use anyhow::{Context, Result};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

pub struct SecretVault;

impl SecretVault {
    /// Resolves any template tokens of format `{{safemca:...}}` within an environment map.
    pub fn resolve_env_map(env_map: &HashMap<String, String>) -> Result<HashMap<String, String>> {
        let mut resolved = HashMap::with_capacity(env_map.len());
        for (key, val) in env_map {
            let resolved_val = Self::resolve_template(val)
                .with_context(|| format!("Failed to resolve secret for environment variable '{}'", key))?;
            resolved.insert(key.clone(), resolved_val);
        }
        Ok(resolved)
    }

    /// Resolves template strings like `{{safemcp:keychain/service}}` or `{{safemcp:env/VAR}}`
    pub fn resolve_template(input: &str) -> Result<String> {
        let mut result = input.to_string();
        for start_tag in ["{{safemcp:", "{{safemca:"] {
            let end_tag = "}}";

            if !result.contains(start_tag) {
                continue;
            }

            let mut iterations = 0;
            const MAX_ITERATIONS: usize = 32;

            while let Some(start_idx) = result.find(start_tag) {
                iterations += 1;
                if iterations > MAX_ITERATIONS {
                    anyhow::bail!("Exceeded maximum recursion depth (32) resolving secret templates");
                }
                let after_start = &result[start_idx + start_tag.len()..];
                if let Some(end_offset) = after_start.find(end_tag) {
                    let token_content = after_start[..end_offset].trim();
                    let secret_value = Self::fetch_secret(token_content)?;
                    let full_placeholder = &result[start_idx..start_idx + start_tag.len() + end_offset + end_tag.len()];
                    result = result.replace(full_placeholder, &secret_value);
                } else {
                    break;
                }
            }
        }

        Ok(result)
    }

    fn fetch_secret(token: &str) -> Result<String> {
        let parts: Vec<&str> = token.splitn(2, ':').collect();
        let (provider, target) = if parts.len() == 2 {
            (parts[0], parts[1])
        } else {
            let slash_parts: Vec<&str> = token.splitn(2, '/').collect();
            if slash_parts.len() == 2 {
                (slash_parts[0], slash_parts[1])
            } else {
                ("env", token)
            }
        };

        match provider.to_lowercase().as_str() {
            "env" => {
                env::var(target).with_context(|| format!("Environment variable '{}' not set", target))
            }
            "keychain" => {
                Self::fetch_from_keychain(target)
            }
            "vault" => {
                Self::fetch_from_file_vault(target)
            }
            other => {
                anyhow::bail!("Unsupported secret provider '{}'. Use 'keychain', 'env', or 'vault'.", other);
            }
        }
    }

    fn fetch_from_keychain(target: &str) -> Result<String> {
        #[cfg(target_os = "macos")]
        {
            let (service, account) = if target.contains('/') {
                let parts: Vec<&str> = target.splitn(2, '/').collect();
                (parts[0], Some(parts[1]))
            } else {
                (target, None)
            };

            let mut cmd = Command::new("security");
            cmd.arg("find-generic-password").arg("-s").arg(service);
            if let Some(acc) = account {
                cmd.arg("-a").arg(acc);
            }
            cmd.arg("-w");

            let output = cmd.output().with_context(|| "Failed to execute macOS security command")?;
            if output.status.success() {
                let secret = String::from_utf8(output.stdout)?.trim().to_string();
                if !secret.is_empty() {
                    return Ok(secret);
                }
            }
            anyhow::bail!("Secret for '{}' not found in macOS Keychain", target);
        }

        #[cfg(target_os = "windows")]
        {
            // Windows Credential Manager lookup via powershell
            let script = format!(
                "[System.Net.NetworkCredential]::new('', (Get-ItemProperty 'HKCU:\\Software\\safeMCP\\Secrets' -ErrorAction SilentlyContinue).{}).Password",
                target
            );
            let output = Command::new("powershell")
                .arg("-NoProfile")
                .arg("-Command")
                .arg(&script)
                .output()?;
            if output.status.success() {
                let secret = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !secret.is_empty() {
                    return Ok(secret);
                }
            }
            anyhow::bail!("Secret for '{}' not found in Windows Credential Manager", target);
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            // Linux: fallback to vault directory or environment
            Self::fetch_from_file_vault(target)
        }
    }

    fn fetch_from_file_vault(target: &str) -> Result<String> {
        let home = dirs::home_dir().context("Could not locate home directory")?;
        let vault_dir = home.join(".safemcp").join("vault");
        let secret_file = vault_dir.join(target);

        if secret_file.exists() {
            let secret = fs::read_to_string(&secret_file)
                .with_context(|| format!("Failed to read secret file {:?}", secret_file))?;
            return Ok(secret.trim().to_string());
        }

        let fallback_file = home.join(".safemca").join("vault").join(target);
        if fallback_file.exists() {
            let secret = fs::read_to_string(&fallback_file)
                .with_context(|| format!("Failed to read secret file {:?}", fallback_file))?;
            return Ok(secret.trim().to_string());
        }

        anyhow::bail!("Secret '{}' not found in vault file {:?}", target, secret_file)
    }

    /// Stores a secret into local safeMCP vault (~/.safemcp/vault/<target>) with 0600 permissions
    pub fn store_in_file_vault(target: &str, secret_value: &str) -> Result<PathBuf> {
        let home = dirs::home_dir().context("Could not locate home directory")?;
        let vault_dir = home.join(".safemcp").join("vault");
        if !vault_dir.exists() {
            fs::create_dir_all(&vault_dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(&vault_dir, fs::Permissions::from_mode(0o700));
            }
        }

        let secret_file = vault_dir.join(target);
        fs::write(&secret_file, secret_value)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&secret_file, fs::Permissions::from_mode(0o600));
        }

        Ok(secret_file)
    }
}
