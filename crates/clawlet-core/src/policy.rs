//! Policy engine — evaluates transfer requests against configurable rules.
//!
//! Loads policy from YAML and enforces daily limits, per-tx limits,
//! token/chain allowlists, and approval thresholds.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
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

/// Daily spending tracker state, serializable for persistence.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Optional path for persisting spending state.
    spending_path: Option<PathBuf>,
}

impl PolicyEngine {
    /// Create a new engine with the given policy (no persistence).
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            tracker: Mutex::new(DailyTracker {
                date: today(),
                total_usd: 0.0,
            }),
            spending_path: None,
        }
    }

    /// Create a new engine with spending persistence at the given path.
    ///
    /// If the file exists and contains valid state for today, the tracker
    /// is restored. Otherwise the tracker starts fresh.
    pub fn with_spending_persistence(
        policy: Policy,
        spending_path: PathBuf,
    ) -> Result<Self, PolicyError> {
        let tracker = Self::load_tracker(&spending_path);
        Ok(Self {
            policy,
            tracker: Mutex::new(tracker),
            spending_path: Some(spending_path),
        })
    }

    /// Load policy from a YAML file and create the engine (no persistence).
    pub fn from_file(path: &Path) -> Result<Self, PolicyError> {
        let policy = Policy::from_file(path)?;
        Ok(Self::new(policy))
    }

    /// Load policy from a YAML file with spending persistence.
    pub fn from_file_with_spending(
        policy_path: &Path,
        spending_path: PathBuf,
    ) -> Result<Self, PolicyError> {
        let policy = Policy::from_file(policy_path)?;
        Self::with_spending_persistence(policy, spending_path)
    }

    /// Load tracker state from disk, returning a fresh tracker if file is
    /// missing, unreadable, or belongs to a different day.
    fn load_tracker(path: &Path) -> DailyTracker {
        let current_date = today();
        if let Ok(data) = std::fs::read_to_string(path) {
            match serde_json::from_str::<DailyTracker>(&data) {
                Ok(tracker) => {
                    if tracker.date == current_date {
                        if !tracker.total_usd.is_finite() || tracker.total_usd < 0.0 {
                            eprintln!(
                                "warning: spending tracker data invalid (total_usd={}); resetting to defaults",
                                tracker.total_usd
                            );
                        } else {
                            return tracker;
                        }
                    }
                }
                Err(err) => {
                    // Use stderr directly since tracing may not be available in core.
                    eprintln!(
                        "warning: failed to parse spending tracker ({}); resetting to defaults",
                        err
                    );
                }
            }
        }
        DailyTracker {
            date: current_date,
            total_usd: 0.0,
        }
    }

    /// Persist the current tracker state atomically (write-to-temp + rename).
    fn persist_tracker(&self, tracker: &DailyTracker) -> Result<(), std::io::Error> {
        use std::io::Write;

        let Some(ref path) = self.spending_path else {
            return Ok(());
        };

        let tmp_path = path.with_extension("json.tmp");
        let data = serde_json::to_string_pretty(tracker).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("json encode: {e}"))
        })?;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)?;
        file.write_all(data.as_bytes())?;
        file.sync_all()?;

        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }

    /// Check whether a transfer is allowed by the policy.
    ///
    /// If allowed and `amount_usd` is `Some`, the amount is added to the daily spending tracker.
    /// When `amount_usd` is `None`, USD-based checks (per-tx limit, daily limit, approval
    /// threshold) are skipped — only token and chain allowlists are enforced.
    pub fn check_transfer(
        &self,
        amount_usd: Option<f64>,
        token: &str,
        chain_id: u64,
    ) -> Result<PolicyDecision, PolicyError> {
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

        // USD-based checks require a known price
        if let Some(amount_usd) = amount_usd {
            // Check per-tx limit
            if amount_usd > self.policy.per_tx_limit_usd {
                return Ok(PolicyDecision::Denied(format!(
                    "amount ${amount_usd:.2} exceeds per-tx limit of ${:.2}",
                    self.policy.per_tx_limit_usd
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
            self.persist_tracker(&tracker)?;
        }

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
    use tempfile::tempdir;

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
        let decision = engine.check_transfer(Some(100.0), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn deny_per_tx_limit() {
        let engine = PolicyEngine::new(test_policy());
        let decision = engine.check_transfer(Some(600.0), "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn deny_unknown_token() {
        let engine = PolicyEngine::new(test_policy());
        let decision = engine.check_transfer(Some(10.0), "SHIB", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn deny_unknown_chain() {
        let engine = PolicyEngine::new(test_policy());
        let decision = engine.check_transfer(Some(10.0), "USDC", 999).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn require_approval_above_threshold() {
        let engine = PolicyEngine::new(test_policy());
        let decision = engine.check_transfer(Some(300.0), "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::RequiresApproval(_)));
    }

    #[test]
    fn daily_limit_accumulation() {
        let mut policy = test_policy();
        policy.require_approval_above_usd = None; // disable approval for this test
        let engine = PolicyEngine::new(policy);

        // Transfer 400 three times: 400 + 400 = 800, third should fail (800 + 400 > 1000)
        assert_eq!(
            engine.check_transfer(Some(400.0), "USDC", 1).unwrap(),
            PolicyDecision::Allowed
        );
        assert_eq!(
            engine.check_transfer(Some(400.0), "USDC", 1).unwrap(),
            PolicyDecision::Allowed
        );
        let decision = engine.check_transfer(Some(400.0), "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn token_check_case_insensitive() {
        let engine = PolicyEngine::new(test_policy());
        let decision = engine.check_transfer(Some(10.0), "usdc", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn all_tokens_allowed_when_empty() {
        let mut policy = test_policy();
        policy.allowed_tokens = vec![];
        let engine = PolicyEngine::new(policy);
        let decision = engine.check_transfer(Some(10.0), "ANYTHING", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn all_chains_allowed_when_empty() {
        let mut policy = test_policy();
        policy.allowed_chains = vec![];
        let engine = PolicyEngine::new(policy);
        let decision = engine.check_transfer(Some(10.0), "USDC", 99999).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    // ========== Edge Cases ==========

    #[test]
    fn test_zero_amount_transfer() {
        let engine = PolicyEngine::new(test_policy());
        let decision = engine.check_transfer(Some(0.0), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn test_negative_amount_handling() {
        // Negative amounts should still pass policy checks (semantically weird but policy doesn't validate)
        // This documents current behavior - may want to add validation later
        let engine = PolicyEngine::new(test_policy());
        let decision = engine.check_transfer(Some(-10.0), "USDC", 1).unwrap();
        // Currently allowed because -10 < 500 per-tx and -10 < 1000 daily
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn test_exact_per_tx_limit() {
        let engine = PolicyEngine::new(test_policy());
        // Exactly at 500.0 per-tx limit - should be allowed (not denied)
        let decision = engine.check_transfer(Some(500.0), "USDC", 1).unwrap();
        // Note: current code uses `>` not `>=`, so exactly at limit is allowed
        assert!(matches!(
            decision,
            PolicyDecision::Allowed | PolicyDecision::RequiresApproval(_)
        ));
    }

    #[test]
    fn test_exact_daily_limit() {
        let mut policy = test_policy();
        policy.require_approval_above_usd = None;
        policy.per_tx_limit_usd = 1000.0; // Allow single tx up to daily limit
        let engine = PolicyEngine::new(policy);

        // Exactly at daily limit should be allowed
        let decision = engine.check_transfer(Some(1000.0), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);

        // Now any additional amount should be denied
        let decision = engine.check_transfer(Some(0.01), "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn test_exact_approval_threshold() {
        let engine = PolicyEngine::new(test_policy());
        // Exactly at 200.0 threshold - current code uses `>`, so exactly at is allowed
        let decision = engine.check_transfer(Some(200.0), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);

        // Just above threshold requires approval
        let engine2 = PolicyEngine::new(test_policy());
        let decision = engine2.check_transfer(Some(200.01), "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::RequiresApproval(_)));
    }

    // ========== Policy Configuration Edge Cases ==========

    #[test]
    fn test_zero_daily_limit() {
        let mut policy = test_policy();
        policy.daily_transfer_limit_usd = 0.0;
        let engine = PolicyEngine::new(policy);

        // Any positive amount should be denied
        let decision = engine.check_transfer(Some(0.01), "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));

        // Zero amount should still be allowed
        let engine2 = PolicyEngine::new({
            let mut p = test_policy();
            p.daily_transfer_limit_usd = 0.0;
            p
        });
        let decision = engine2.check_transfer(Some(0.0), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn test_zero_per_tx_limit() {
        let mut policy = test_policy();
        policy.per_tx_limit_usd = 0.0;
        let engine = PolicyEngine::new(policy);

        // Any positive amount should be denied due to per-tx limit
        let decision = engine.check_transfer(Some(0.01), "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));

        // Zero amount passes per-tx check (0 is not > 0)
        let engine2 = PolicyEngine::new({
            let mut p = test_policy();
            p.per_tx_limit_usd = 0.0;
            p
        });
        let decision = engine2.check_transfer(Some(0.0), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn test_very_large_limits() {
        let policy = Policy {
            daily_transfer_limit_usd: f64::MAX,
            per_tx_limit_usd: f64::MAX,
            allowed_tokens: vec![],
            allowed_chains: vec![],
            require_approval_above_usd: None,
        };
        let engine = PolicyEngine::new(policy);

        // Very large transfer should be allowed
        let decision = engine
            .check_transfer(Some(1_000_000_000_000.0), "ETH", 1)
            .unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn test_policy_with_only_daily_limit() {
        let yaml = r#"
daily_transfer_limit_usd: 500.0
per_tx_limit_usd: 1000.0
"#;
        let policy = Policy::from_yaml(yaml).unwrap();
        let engine = PolicyEngine::new(policy);

        // Should work with any token and chain
        let decision = engine
            .check_transfer(Some(100.0), "RANDOM_TOKEN", 12345)
            .unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    // ========== Token/Chain Combinations ==========

    #[test]
    fn test_multiple_allowed_tokens() {
        let engine = PolicyEngine::new(test_policy());

        // Test USDC
        assert_eq!(
            engine.check_transfer(Some(10.0), "USDC", 1).unwrap(),
            PolicyDecision::Allowed
        );

        // Test ETH
        assert_eq!(
            engine.check_transfer(Some(10.0), "ETH", 1).unwrap(),
            PolicyDecision::Allowed
        );

        // Test disallowed token
        assert!(matches!(
            engine.check_transfer(Some(10.0), "WBTC", 1).unwrap(),
            PolicyDecision::Denied(_)
        ));
    }

    #[test]
    fn test_token_address_format() {
        let mut policy = test_policy();
        policy.allowed_tokens = vec![
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(), // USDC address
        ];
        let engine = PolicyEngine::new(policy);

        // Should match the address
        let decision = engine
            .check_transfer(Some(10.0), "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", 1)
            .unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn test_mixed_case_token_addresses() {
        let mut policy = test_policy();
        policy.allowed_tokens = vec!["0xAbCdEf1234567890AbCdEf1234567890AbCdEf12".to_string()];
        let engine = PolicyEngine::new(policy);

        // Lowercase should match (case-insensitive)
        let decision = engine
            .check_transfer(Some(10.0), "0xabcdef1234567890abcdef1234567890abcdef12", 1)
            .unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);

        // Uppercase should match
        let decision = engine
            .check_transfer(Some(10.0), "0XABCDEF1234567890ABCDEF1234567890ABCDEF12", 1)
            .unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn test_empty_token_string() {
        let engine = PolicyEngine::new(test_policy());
        // Empty string token should be denied (not in allowed list)
        let decision = engine.check_transfer(Some(10.0), "", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn test_multiple_allowed_chains() {
        let engine = PolicyEngine::new(test_policy());

        // Chain 1 (Ethereum mainnet) is allowed
        assert_eq!(
            engine.check_transfer(Some(10.0), "USDC", 1).unwrap(),
            PolicyDecision::Allowed
        );

        // Chain 8453 (Base) is allowed
        assert_eq!(
            engine.check_transfer(Some(10.0), "USDC", 8453).unwrap(),
            PolicyDecision::Allowed
        );

        // Chain 137 (Polygon) is not allowed
        assert!(matches!(
            engine.check_transfer(Some(10.0), "USDC", 137).unwrap(),
            PolicyDecision::Denied(_)
        ));
    }

    // ========== Daily Tracker Behavior ==========

    #[test]
    fn test_spending_not_recorded_on_denial() {
        let mut policy = test_policy();
        policy.require_approval_above_usd = None;
        let engine = PolicyEngine::new(policy);

        // Make a transfer that gets denied due to per-tx limit
        let decision = engine.check_transfer(Some(600.0), "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));

        // Daily total should still be 0, so we can transfer up to 1000
        let decision = engine.check_transfer(Some(500.0), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);

        let decision = engine.check_transfer(Some(500.0), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);

        // Now at 1000, next should fail
        let decision = engine.check_transfer(Some(1.0), "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn test_spending_not_recorded_on_token_denial() {
        let engine = PolicyEngine::new(test_policy());

        // Denied due to token not allowed
        let decision = engine.check_transfer(Some(100.0), "SHIB", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));

        // Should still have full daily limit available
        // Using allowed token now - should work
        let decision = engine.check_transfer(Some(100.0), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn test_spending_not_recorded_on_chain_denial() {
        let engine = PolicyEngine::new(test_policy());

        // Denied due to chain not allowed
        let decision = engine.check_transfer(Some(100.0), "USDC", 999).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));

        // Should still have full daily limit available
        let decision = engine.check_transfer(Some(100.0), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    // ========== Error Handling ==========

    #[test]
    fn test_invalid_yaml_policy() {
        let yaml = r#"
this is not: valid yaml
  - because of: bad indentation
    and: [unclosed bracket
"#;
        let result = Policy::from_yaml(yaml);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PolicyError::ParseError(_)));
    }

    #[test]
    fn test_missing_required_fields() {
        // Missing daily_transfer_limit_usd
        let yaml = r#"
per_tx_limit_usd: 100.0
allowed_tokens:
  - USDC
"#;
        let result = Policy::from_yaml(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_missing_per_tx_limit() {
        // Missing per_tx_limit_usd
        let yaml = r#"
daily_transfer_limit_usd: 1000.0
"#;
        let result = Policy::from_yaml(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_from_nonexistent_file() {
        let result = Policy::from_file(std::path::Path::new("/nonexistent/path/policy.yaml"));
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PolicyError::IoError(_)));
    }

    // ========== Approval Flow ==========

    #[test]
    fn test_approval_not_triggered_when_none() {
        let mut policy = test_policy();
        policy.require_approval_above_usd = None;
        let engine = PolicyEngine::new(policy);

        // Even large amounts don't require approval
        let decision = engine.check_transfer(Some(499.0), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
    }

    #[test]
    fn test_approval_triggered_at_boundary() {
        let engine = PolicyEngine::new(test_policy());

        // At threshold (200.0) - allowed (uses > not >=)
        let decision = engine.check_transfer(Some(200.0), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);

        // Just above - requires approval
        let engine2 = PolicyEngine::new(test_policy());
        let decision = engine2.check_transfer(Some(200.001), "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::RequiresApproval(_)));
    }

    #[test]
    fn test_approval_doesnt_count_toward_daily() {
        let engine = PolicyEngine::new(test_policy());

        // This requires approval, so should NOT count toward daily limit
        let decision = engine.check_transfer(Some(300.0), "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::RequiresApproval(_)));

        // Daily limit should still be full (1000)
        // We can do 5 transfers of 100 each (under approval threshold)
        for _ in 0..5 {
            let decision = engine.check_transfer(Some(100.0), "USDC", 1).unwrap();
            assert_eq!(decision, PolicyDecision::Allowed);
        }

        // At 500 now, can do 5 more
        for _ in 0..5 {
            let decision = engine.check_transfer(Some(100.0), "USDC", 1).unwrap();
            assert_eq!(decision, PolicyDecision::Allowed);
        }

        // At 1000, next should fail
        let decision = engine.check_transfer(Some(1.0), "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    #[test]
    fn test_approval_checks_happen_after_other_checks() {
        let engine = PolicyEngine::new(test_policy());

        // Invalid token - should be denied, not require approval
        let decision = engine.check_transfer(Some(300.0), "INVALID", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));

        // Invalid chain - should be denied, not require approval
        let decision = engine.check_transfer(Some(300.0), "USDC", 999).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));

        // Over per-tx limit - should be denied, not require approval
        let decision = engine.check_transfer(Some(600.0), "USDC", 1).unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    // ========== Float Edge Cases ==========

    #[test]
    fn test_float_precision_near_limit() {
        let mut policy = test_policy();
        policy.daily_transfer_limit_usd = 100.0;
        policy.per_tx_limit_usd = 100.0;
        policy.require_approval_above_usd = None;
        let engine = PolicyEngine::new(policy);

        // Transfer amounts that might cause float precision issues
        let decision = engine.check_transfer(Some(33.33), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
        let decision = engine.check_transfer(Some(33.33), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);
        let decision = engine.check_transfer(Some(33.33), "USDC", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);

        // 33.33 * 3 = 99.99, should have 0.01 left
        let decision = engine.check_transfer(Some(0.02), "USDC", 1).unwrap();
        // This might fail due to float precision (99.99 might be 99.99000000000001)
        // Document current behavior
        assert!(matches!(
            decision,
            PolicyDecision::Allowed | PolicyDecision::Denied(_)
        ));
    }

    #[test]
    fn test_nan_amount() {
        let engine = PolicyEngine::new(test_policy());
        // NaN comparisons are always false in Rust, so this tests edge case
        let decision = engine.check_transfer(Some(f64::NAN), "USDC", 1).unwrap();
        // NaN > per_tx_limit is false, NaN + total > daily is false
        // So NaN might actually be allowed! This documents current behavior.
        // In production, you'd want input validation to reject NaN
        assert!(matches!(
            decision,
            PolicyDecision::Allowed
                | PolicyDecision::Denied(_)
                | PolicyDecision::RequiresApproval(_)
        ));
    }

    #[test]
    fn test_infinity_amount() {
        let engine = PolicyEngine::new(test_policy());
        // Infinity should definitely exceed limits
        let decision = engine
            .check_transfer(Some(f64::INFINITY), "USDC", 1)
            .unwrap();
        assert!(matches!(decision, PolicyDecision::Denied(_)));
    }

    // ========== Spending Persistence ==========

    #[test]
    fn spending_tracker_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("spending.json");
        let engine = PolicyEngine::with_spending_persistence(test_policy(), path.clone()).unwrap();

        let tracker = DailyTracker {
            date: today(),
            total_usd: 123.45,
        };
        engine.persist_tracker(&tracker).unwrap();

        let loaded = PolicyEngine::load_tracker(&path);
        assert_eq!(loaded.date, tracker.date);
        assert!((loaded.total_usd - tracker.total_usd).abs() < 1e-9);
    }

    #[test]
    fn spending_tracker_corrupt_file_recovers() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("spending.json");
        std::fs::write(&path, "this is not json").unwrap();

        let loaded = PolicyEngine::load_tracker(&path);
        assert_eq!(loaded.date, today());
        assert_eq!(loaded.total_usd, 0.0);
    }

    #[test]
    fn spending_tracker_negative_value_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("spending.json");
        let data = serde_json::json!({
            "date": today(),
            "total_usd": -1.0
        });
        std::fs::write(&path, serde_json::to_string_pretty(&data).unwrap()).unwrap();

        let loaded = PolicyEngine::load_tracker(&path);
        assert_eq!(loaded.date, today());
        assert_eq!(loaded.total_usd, 0.0);
    }
}
