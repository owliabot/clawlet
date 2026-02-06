//! Configuration parser for Clawlet.
//!
//! Loads and validates the main `config.yaml` file.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Authentication configuration.
///
/// Password verification is now done by attempting to unlock the keystore.
/// The `password_hash` field is deprecated and ignored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Argon2id hash of the admin password, set during init.
    ///
    /// **Deprecated**: This field is no longer used. Password verification
    /// is now done by attempting to unlock the keystore. This field is kept
    /// for backwards compatibility with existing config files.
    #[deprecated(
        since = "0.2.0",
        note = "password verification now uses keystore unlock instead of stored hash"
    )]
    #[serde(default)]
    pub password_hash: Option<String>,
    /// Default session TTL in hours (default: 24).
    #[serde(default = "default_session_ttl_hours")]
    pub default_session_ttl_hours: u64,
    /// Maximum failed authentication attempts before lockout (default: 5).
    #[serde(default = "default_max_failed_attempts")]
    pub max_failed_attempts: u32,
    /// Lockout duration in minutes after max failed attempts (default: 15).
    #[serde(default = "default_lockout_minutes")]
    pub lockout_minutes: u32,
}

fn default_session_ttl_hours() -> u64 {
    24
}

fn default_max_failed_attempts() -> u32 {
    5
}

fn default_lockout_minutes() -> u32 {
    15
}

#[allow(deprecated)]
impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            password_hash: None,
            default_session_ttl_hours: default_session_ttl_hours(),
            max_failed_attempts: default_max_failed_attempts(),
            lockout_minutes: default_lockout_minutes(),
        }
    }
}

/// Top-level Clawlet configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Path to the policy YAML file.
    pub policy_path: PathBuf,
    /// Path to the encrypted keystore directory.
    pub keystore_path: PathBuf,
    /// Address to bind the RPC server to.
    #[serde(default = "default_rpc_bind")]
    pub rpc_bind: String,
    /// Path to the audit log file.
    pub audit_log_path: PathBuf,
    /// Mapping of chain ID → RPC URL.
    #[serde(default)]
    pub chain_rpc_urls: HashMap<u64, String>,
    /// Authentication configuration.
    #[serde(default)]
    pub auth: AuthConfig,
}

fn default_rpc_bind() -> String {
    "127.0.0.1:9100".to_string()
}

impl Config {
    /// Load configuration from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        serde_yaml::from_str(yaml)
    }

    /// Load configuration from a YAML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        Ok(Self::from_yaml(&contents)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_config() {
        let yaml = r#"
policy_path: /etc/clawlet/policy.yaml
keystore_path: /etc/clawlet/keystore
rpc_bind: "0.0.0.0:9200"
audit_log_path: /var/log/clawlet/audit.jsonl
chain_rpc_urls:
  1: "https://eth-mainnet.example.com"
  8453: "https://base.example.com"
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.policy_path,
            PathBuf::from("/etc/clawlet/policy.yaml")
        );
        assert_eq!(config.rpc_bind, "0.0.0.0:9200");
        assert_eq!(config.chain_rpc_urls.len(), 2);
        assert!(config.chain_rpc_urls.contains_key(&8453));
    }

    #[test]
    fn default_rpc_bind_value() {
        let yaml = r#"
policy_path: policy.yaml
keystore_path: keystore
audit_log_path: audit.jsonl
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.rpc_bind, "127.0.0.1:9100");
    }

    #[test]
    fn missing_required_field() {
        let yaml = r#"
policy_path: policy.yaml
"#;
        assert!(Config::from_yaml(yaml).is_err());
    }
}
