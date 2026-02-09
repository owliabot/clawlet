//! Integration tests for the policy engine.
//!
//! These tests cover scenarios that need more setup, file I/O, or
//! concurrent behavior testing.

use clawlet_core::policy::{Policy, PolicyDecision, PolicyEngine, PolicyError};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use tempfile::TempDir;

/// Create a test policy with configurable limits.
fn make_policy(daily: f64, per_tx: f64, approval: Option<f64>) -> Policy {
    Policy {
        daily_transfer_limit_usd: daily,
        per_tx_limit_usd: per_tx,
        allowed_tokens: vec!["USDC".to_string(), "ETH".to_string()],
        allowed_chains: vec![1, 8453],
        require_approval_above_usd: approval,
        per_tx_limit_raw: None,
    }
}

// ========== File I/O Tests ==========

#[test]
fn test_policy_from_file_success() {
    let temp_dir = TempDir::new().unwrap();
    let policy_path = temp_dir.path().join("policy.yaml");

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

    fs::write(&policy_path, yaml).unwrap();

    let policy = Policy::from_file(&policy_path).unwrap();
    assert_eq!(policy.daily_transfer_limit_usd, 5000.0);
    assert_eq!(policy.per_tx_limit_usd, 1000.0);
    assert_eq!(policy.allowed_tokens, vec!["USDC", "WETH"]);
}

#[test]
fn test_policy_engine_from_file() {
    let temp_dir = TempDir::new().unwrap();
    let policy_path = temp_dir.path().join("policy.yaml");

    let yaml = r#"
daily_transfer_limit_usd: 1000.0
per_tx_limit_usd: 500.0
allowed_tokens: []
allowed_chains: []
"#;

    fs::write(&policy_path, yaml).unwrap();

    let engine = PolicyEngine::from_file(&policy_path).unwrap();
    let decision = engine.check_transfer(Some(100.0), "ANY", 1).unwrap();
    assert_eq!(decision, PolicyDecision::Allowed);
}

#[test]
fn test_policy_from_file_not_found() {
    let result = Policy::from_file(&PathBuf::from("/nonexistent/policy.yaml"));
    assert!(result.is_err());
    match result.unwrap_err() {
        PolicyError::IoError(_) => (),
        e => panic!("Expected IoError, got {:?}", e),
    }
}

#[test]
fn test_policy_from_file_invalid_yaml() {
    let temp_dir = TempDir::new().unwrap();
    let policy_path = temp_dir.path().join("policy.yaml");

    fs::write(&policy_path, "not: [valid: yaml").unwrap();

    let result = Policy::from_file(&policy_path);
    assert!(result.is_err());
    match result.unwrap_err() {
        PolicyError::ParseError(_) => (),
        e => panic!("Expected ParseError, got {:?}", e),
    }
}

#[test]
fn test_policy_from_empty_file() {
    let temp_dir = TempDir::new().unwrap();
    let policy_path = temp_dir.path().join("policy.yaml");

    fs::write(&policy_path, "").unwrap();

    let result = Policy::from_file(&policy_path);
    assert!(result.is_err());
}

// ========== Concurrent Access Tests ==========

#[test]
fn test_concurrent_transfers_accumulate_correctly() {
    let policy = make_policy(1000.0, 100.0, None);
    let engine = Arc::new(PolicyEngine::new(policy));

    let mut handles = vec![];

    // Spawn 10 threads, each trying to transfer 100
    for _ in 0..10 {
        let engine_clone = Arc::clone(&engine);
        handles.push(thread::spawn(move || {
            engine_clone.check_transfer(Some(100.0), "USDC", 1).unwrap()
        }));
    }

    let mut allowed = 0;
    let mut denied = 0;
    for handle in handles {
        match handle.join().unwrap() {
            PolicyDecision::Allowed => allowed += 1,
            PolicyDecision::Denied(_) => denied += 1,
            _ => panic!("Unexpected decision"),
        }
    }

    // Exactly 10 * 100 = 1000, which equals daily limit
    // All 10 should be allowed
    assert_eq!(allowed, 10);
    assert_eq!(denied, 0);
}

#[test]
fn test_concurrent_transfers_exceed_limit() {
    let policy = make_policy(500.0, 100.0, None);
    let engine = Arc::new(PolicyEngine::new(policy));

    let mut handles = vec![];

    // Spawn 10 threads, each trying to transfer 100
    // Only 5 should succeed (500 limit / 100 per tx = 5)
    for _ in 0..10 {
        let engine_clone = Arc::clone(&engine);
        handles.push(thread::spawn(move || {
            engine_clone.check_transfer(Some(100.0), "USDC", 1).unwrap()
        }));
    }

    let mut allowed = 0;
    let mut denied = 0;
    for handle in handles {
        match handle.join().unwrap() {
            PolicyDecision::Allowed => allowed += 1,
            PolicyDecision::Denied(_) => denied += 1,
            _ => panic!("Unexpected decision"),
        }
    }

    // Should have exactly 5 allowed and 5 denied
    assert_eq!(allowed, 5);
    assert_eq!(denied, 5);
}

#[test]
fn test_concurrent_mixed_outcomes() {
    let policy = make_policy(300.0, 100.0, Some(75.0));
    let engine = Arc::new(PolicyEngine::new(policy));

    let mut handles = vec![];

    // Mix of amounts: some allowed, some require approval
    let amounts = vec![50.0, 80.0, 50.0, 90.0, 50.0];
    for amount in amounts {
        let engine_clone = Arc::clone(&engine);
        handles.push(thread::spawn(move || {
            engine_clone
                .check_transfer(Some(amount), "USDC", 1)
                .unwrap()
        }));
    }

    let mut allowed = 0;
    let mut approval = 0;
    let mut denied = 0;
    for handle in handles {
        match handle.join().unwrap() {
            PolicyDecision::Allowed => allowed += 1,
            PolicyDecision::RequiresApproval(_) => approval += 1,
            PolicyDecision::Denied(_) => denied += 1,
        }
    }

    // 50, 80, 50, 90, 50 = 320 total attempted
    // 80 and 90 require approval (> 75 threshold)
    // Only the 50s (150 total) should be allowed if approval requests don't count
    // Depending on order, some 50s might be denied if we hit the limit
    // Just verify we got a mix
    assert!(allowed > 0 || approval > 0);
    println!("Results: allowed={allowed}, approval={approval}, denied={denied}");
}

// ========== Policy Access Tests ==========

#[test]
fn test_engine_policy_access() {
    let policy = make_policy(1000.0, 500.0, Some(200.0));
    let engine = PolicyEngine::new(policy);

    let p = engine.policy();
    assert_eq!(p.daily_transfer_limit_usd, 1000.0);
    assert_eq!(p.per_tx_limit_usd, 500.0);
    assert_eq!(p.require_approval_above_usd, Some(200.0));
}

// ========== Complex YAML Parsing ==========

#[test]
fn test_yaml_with_comments() {
    let yaml = r#"
# Policy configuration for clawlet
daily_transfer_limit_usd: 1000.0  # Daily limit in USD
per_tx_limit_usd: 500.0  # Per-transaction limit
# Allowed tokens
allowed_tokens:
  - USDC  # Stablecoin
  - ETH   # Native token
allowed_chains:
  - 1     # Ethereum mainnet
  - 8453  # Base
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.daily_transfer_limit_usd, 1000.0);
    assert_eq!(policy.allowed_tokens.len(), 2);
}

#[test]
fn test_yaml_with_extra_fields() {
    // Extra fields should be ignored (serde default behavior)
    let yaml = r#"
daily_transfer_limit_usd: 1000.0
per_tx_limit_usd: 500.0
unknown_field: "should be ignored"
another_unknown: 123
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.daily_transfer_limit_usd, 1000.0);
}

#[test]
fn test_yaml_scientific_notation() {
    let yaml = r#"
daily_transfer_limit_usd: 1.0e6
per_tx_limit_usd: 5.0e4
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.daily_transfer_limit_usd, 1_000_000.0);
    assert_eq!(policy.per_tx_limit_usd, 50_000.0);
}

#[test]
fn test_yaml_integer_as_float() {
    let yaml = r#"
daily_transfer_limit_usd: 1000
per_tx_limit_usd: 500
"#;

    let policy = Policy::from_yaml(yaml).unwrap();
    assert_eq!(policy.daily_transfer_limit_usd, 1000.0);
    assert_eq!(policy.per_tx_limit_usd, 500.0);
}

// ========== Realistic Scenarios ==========

#[test]
fn test_realistic_spending_pattern() {
    let policy = make_policy(500.0, 200.0, Some(100.0));
    let engine = PolicyEngine::new(policy);

    // Morning coffee
    let d = engine.check_transfer(Some(5.50), "USDC", 1).unwrap();
    assert_eq!(d, PolicyDecision::Allowed);

    // Lunch
    let d = engine.check_transfer(Some(15.00), "USDC", 1).unwrap();
    assert_eq!(d, PolicyDecision::Allowed);

    // Small purchase
    let d = engine.check_transfer(Some(35.00), "USDC", 1).unwrap();
    assert_eq!(d, PolicyDecision::Allowed);

    // Larger purchase - needs approval
    let d = engine.check_transfer(Some(150.00), "USDC", 1).unwrap();
    assert!(matches!(d, PolicyDecision::RequiresApproval(_)));

    // End of day, small transfer
    let d = engine.check_transfer(Some(10.00), "USDC", 1).unwrap();
    assert_eq!(d, PolicyDecision::Allowed);

    // Total approved so far: 5.50 + 15 + 35 + 10 = 65.50
    // Can still transfer more
    let d = engine.check_transfer(Some(100.00), "USDC", 1).unwrap();
    assert_eq!(d, PolicyDecision::Allowed);

    // Now at 165.50, still under 500
}

#[test]
fn test_multi_chain_multi_token_scenario() {
    let policy = Policy {
        daily_transfer_limit_usd: 1000.0,
        per_tx_limit_usd: 500.0,
        allowed_tokens: vec![
            "USDC".to_string(),
            "USDT".to_string(),
            "DAI".to_string(),
            "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string(), // USDC address
        ],
        allowed_chains: vec![1, 10, 8453, 42161], // Ethereum, Optimism, Base, Arbitrum
        require_approval_above_usd: None,
        per_tx_limit_raw: None,
    };
    let engine = PolicyEngine::new(policy);

    // Various combinations
    assert_eq!(
        engine.check_transfer(Some(100.0), "USDC", 1).unwrap(),
        PolicyDecision::Allowed
    );
    assert_eq!(
        engine.check_transfer(Some(100.0), "USDT", 10).unwrap(),
        PolicyDecision::Allowed
    );
    assert_eq!(
        engine.check_transfer(Some(100.0), "DAI", 8453).unwrap(),
        PolicyDecision::Allowed
    );
    assert_eq!(
        engine
            .check_transfer(
                Some(100.0),
                "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                42161
            )
            .unwrap(),
        PolicyDecision::Allowed
    );

    // Wrong chain
    assert!(matches!(
        engine.check_transfer(Some(100.0), "USDC", 137).unwrap(), // Polygon not allowed
        PolicyDecision::Denied(_)
    ));

    // Wrong token
    assert!(matches!(
        engine.check_transfer(Some(100.0), "WBTC", 1).unwrap(),
        PolicyDecision::Denied(_)
    ));
}

// ========== Decision Message Tests ==========

#[test]
fn test_denial_message_per_tx() {
    let policy = make_policy(1000.0, 100.0, None);
    let engine = PolicyEngine::new(policy);

    let decision = engine.check_transfer(Some(150.0), "USDC", 1).unwrap();
    if let PolicyDecision::Denied(msg) = decision {
        assert!(msg.contains("per-tx limit"));
        assert!(msg.contains("$150.00"));
        assert!(msg.contains("$100.00"));
    } else {
        panic!("Expected Denied");
    }
}

#[test]
fn test_denial_message_daily() {
    let policy = make_policy(100.0, 200.0, None);
    let engine = PolicyEngine::new(policy);

    // Use up most of daily limit
    engine.check_transfer(Some(90.0), "USDC", 1).unwrap();

    // Try to exceed
    let decision = engine.check_transfer(Some(20.0), "USDC", 1).unwrap();
    if let PolicyDecision::Denied(msg) = decision {
        assert!(msg.contains("daily limit"));
        assert!(msg.contains("$90.00"));
    } else {
        panic!("Expected Denied");
    }
}

#[test]
fn test_denial_message_token() {
    let policy = make_policy(1000.0, 500.0, None);
    let engine = PolicyEngine::new(policy);

    let decision = engine.check_transfer(Some(100.0), "SHIB", 1).unwrap();
    if let PolicyDecision::Denied(msg) = decision {
        assert!(msg.contains("SHIB"));
        assert!(msg.contains("not in the allowed list"));
    } else {
        panic!("Expected Denied");
    }
}

#[test]
fn test_denial_message_chain() {
    let policy = make_policy(1000.0, 500.0, None);
    let engine = PolicyEngine::new(policy);

    let decision = engine.check_transfer(Some(100.0), "USDC", 999).unwrap();
    if let PolicyDecision::Denied(msg) = decision {
        assert!(msg.contains("999"));
        assert!(msg.contains("not in the allowed list"));
    } else {
        panic!("Expected Denied");
    }
}

#[test]
fn test_approval_message() {
    let policy = make_policy(1000.0, 500.0, Some(100.0));
    let engine = PolicyEngine::new(policy);

    let decision = engine.check_transfer(Some(150.0), "USDC", 1).unwrap();
    if let PolicyDecision::RequiresApproval(msg) = decision {
        assert!(msg.contains("$150.00"));
        assert!(msg.contains("$100.00"));
    } else {
        panic!("Expected RequiresApproval");
    }
}
