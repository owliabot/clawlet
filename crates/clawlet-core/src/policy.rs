//! Policy engine — evaluates transfer requests against configurable rules.
//!
//! Loads policy from YAML and enforces daily limits, per-tx limits,
//! token/chain allowlists, and approval thresholds.

use serde::Deserialize;
use std::sync::Mutex;
use thiserror::Error;

/// Errors from the policy engine.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to parse policy YAML: {0}")]
    ParseError(#[from] serde_yaml::Error),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("internal lock error")]
    LockError,
}

/// Result of a policy evaluation.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
    /// The operation is allowed.
    Allowed,
    /// The operation is denied, with a reason.
    Denied(String),
    /// The operation requires human approval.
    RequiresApproval(String),
}

/// Policy rules parsed from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct Policy {
    /// Maximum total USD value of transfers per day.
    pub daily_transfer_limit_usd: f64,
    /// Maximum USD value per single transfer.
    pub per_tx_limit_usd: f64,
    /// Allowed token symbols or addresses (empty = all allowed).
    #[serde(default)]
    pub allowed_tokens: Vec<String>,
    /// Allowed chain IDs (empty = all allowed).
    #[serde(default)]
    pub allowed_chains: Vec<u64>,
    /// If set, transfers above this USD value require human approval.
    pub require_approval_above_usd: Option<f64>,
}

impl Policy {
    /// Parse policy from a YAML string.
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    /// Load policy from a YAML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, PolicyError> {
        let contents = std::fs::read_to_string(path)?;
        Self::from_yaml(&contents)
    }
}

/// In-memory daily spending tracker.
struct DailyTracker {
    /// The date string (YYYY-MM-DD) for the current tracking period.
    date: String,
    /// Total USD spent today.
    total_usd: f64,
}

/// Policy engine that evaluates transfer requests.
pub struct PolicyEngine {
    policy: Policy,
    tracker: Mutex<DailyTracker>,
}

impl PolicyEngine {
    /// Create a new engine with the given policy.
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            tracker: Mutex::new(DailyTracker {
                date: today(),
                total_usd: 0.0,
            }),
        }
    }

    /// Load policy from a YAML file and create the engine.
    pub fn from_file(path: &std::path::Path) -> Result<Self, PolicyError> {
        let policy = Policy::from_file(path)?;
        Ok(Self::new(policy))
    }

    /// Check whether a transfer is allowed by the policy.
    ///
    /// If allowed, the amount is added to the daily spending tracker.
    pub fn check_transfer(
        &self,
        amount_usd: f64,
        token: &str,
        chain_id: u64,
    ) -> Result<PolicyDecision, PolicyError> {
        // Check per-tx limit
        if amount_usd > self.policy.per_tx_limit_usd {
            return Ok(PolicyDecision::Denied(format!(
                "amount ${amount_usd:.2} exceeds per-tx limit of ${:.2}",
                self.policy.per_tx_limit_usd
            )));
        }

        // Check allowed tokens (empty = all allowed)
        if !self.policy.allowed_tokens.is_empty()
            && !self
                .policy
                .allowed_tokens
                .iter()
                .any(|t| t.eq_ignore_ascii_case(token))
        {
            return Ok(PolicyDecision::Denied(format!(
                "token '{token}' is not in the allowed list"
            )));
        }

        // Check allowed chains (empty = all allowed)
        if !self.policy.allowed_chains.is_empty() && !self.policy.allowed_chains.contains(&chain_id)
        {
            return Ok(PolicyDecision::Denied(format!(
                "chain {chain_id} is not in the allowed list"
            )));
        }

        // Check daily limit
        let mut tracker = self.tracker.lock().map_err(|_| PolicyError::LockError)?;
        let current_date = today();
        if tracker.date != current_date {
            // New day — reset tracker
            tracker.date = current_date;
            tracker.total_usd = 0.0;
        }

        if tracker.total_usd + amount_usd > self.policy.daily_transfer_limit_usd {
            return Ok(PolicyDecision::Denied(format!(
                "daily limit would be exceeded: ${:.2} spent + ${amount_usd:.2} > ${:.2} limit",
                tracker.total_usd, self.policy.daily_transfer_limit_usd
            )));
        }

        // Check approval threshold
        if let Some(threshold) = self.policy.require_approval_above_usd {
            if amount_usd > threshold {
                return Ok(PolicyDecision::RequiresApproval(format!(
                    "amount ${amount_usd:.2} exceeds approval threshold of ${threshold:.2}"
                )));
            }
        }

        // All checks passed — record spending
        tracker.total_usd += amount_usd;

        Ok(PolicyDecision::Allowed)
    }

    /// Get a reference to the loaded policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}

fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> Policy {
        Policy {
            daily_transfer_limit_usd: 1000.0,
            per_tx_limit_usd: 500.0,
            allowed_tokens: vec!["USDC".to_string(), "ETH".to_string()],
            allowed_chains: vec![1, 8453],
            require_approval_above_usd: Some(200.0),
        }
    }

    #[test]
    fn parse_policy_yaml() {
        let yaml = r#"
daily_transfer_limit_usd: 5000.0
per_tx_limit_usd: 1000.0
allowed_tokens:
  - USDC
  - WETH
allowed_chains:
  - 1
  - 8453
require_approval_above_usd: 500.0
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert_eq!(policy.daily_transfer_limit_usd, 5000.0);
        assert_eq!(policy.per_tx_limit_usd, 1000.0);
        assert_eq!(policy.allowed_tokens, vec!["USDC", "WETH"]);
        assert_eq!(policy.allowed_chains, vec![1, 8453]);
        assert_eq!(policy.require_approval_above_usd, Some(500.0));
    }

    #[test]
    fn parse_minimal_policy() {
        let yaml = r#"
daily_transfer_limit_usd: 100.0
per_tx_limit_usd: 50.0
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        assert!(policy.allowed_tokens.is_empty());
        assert!(policy.allowed_chains.is_empty());
        assert!(policy.require_approval_above_usd.is_none());
    }

    #[test]
    fn allow_transfer() {
        let engine = PolicyEngine::new(test_policy());
        let decision = engine.check_transfer(100.0, "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn deny_per_tx_limit() {
        let engine = PolicyEngine::new(test_policy());
        let decision = engine.check_transfer(600.0, "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn deny_unknown_token() {
        let engine = PolicyEngine::new(test_policy());
        let decision = engine.check_transfer(10.0, "SHIB", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn deny_unknown_chain() {
        let engine = PolicyEngine::new(test_policy());
        let decision = engine.check_transfer(10.0, "USDC", 999).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn require_approval_above_threshold() {
        let engine = PolicyEngine::new(test_policy());
        let decision = engine.check_transfer(300.0, "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::RequiresApproval(_)));
    }

    #[test]
    fn daily_limit_accumulation() {
        let mut policy = test_policy();
        policy.require_approval_above_usd = None; // disable approval for this test
        let engine = PolicyEngine::new(policy);

        // Transfer 400 three times: 400 + 400 = 800, third should fail (800 + 400 > 1000)
        assert_eq!(
            engine.check_transfer(400.0, "USDC", 1).unwrap(),
            PolicyDecision::Allowed
        );
        assert_eq!(
            engine.check_transfer(400.0, "USDC", 1).unwrap(),
            PolicyDecision::Allowed
        );
        let decision = engine.check_transfer(400.0, "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn token_check_case_insensitive() {
        let engine = PolicyEngine::new(test_policy());
        let decision = engine.check_transfer(10.0, "usdc", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn all_tokens_allowed_when_empty() {
        let mut policy = test_policy();
        policy.allowed_tokens = vec![];
        let engine = PolicyEngine::new(policy);
        let decision = engine.check_transfer(10.0, "ANYTHING", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn all_chains_allowed_when_empty() {
        let mut policy = test_policy();
        policy.allowed_chains = vec![];
        let engine = PolicyEngine::new(policy);
        let decision = engine.check_transfer(10.0, "USDC", 99999).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }
}
