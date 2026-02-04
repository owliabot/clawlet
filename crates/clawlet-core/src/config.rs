//! Policy YAML configuration parser.
//!
//! Loads and validates `policy.yaml` files into Rust types.

/// Parsed policy configuration.
#[derive(Debug, Clone)]
pub struct PolicyConfig {
    /// Maximum daily transfer in USD equivalent.
    pub daily_limit_usd: f64,
    /// Allowed ERC-20 token addresses.
    pub allowed_tokens: Vec<String>,
    /// Allowed recipient addresses (empty = any).
    pub allowed_recipients: Vec<String>,
}

/// Loads a policy configuration from a YAML file path.
///
/// # Panics
/// Not yet implemented.
pub fn load(_path: &str) -> PolicyConfig {
    todo!("M1-1: implement YAML policy loading")
}
