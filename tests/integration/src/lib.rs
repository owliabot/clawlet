//! Integration tests for Clawlet.
//!
//! Tests that require a running Anvil instance are marked `#[ignore]`.
//! Run them locally with:
//!
//! ```bash
//! anvil &
//! cargo test -p clawlet-integration-tests -- --ignored
//! ```

#[cfg(test)]
mod tests {
    use clawlet_core::audit::{AuditEvent, AuditLogger};
    use clawlet_core::policy::{Policy, PolicyDecision, PolicyEngine};
    use serde_json::json;

    // -----------------------------------------------------------------
    // test_full_init_flow — exercises keystore + config + policy creation
    // -----------------------------------------------------------------

    #[test]
    fn test_full_init_flow() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join(".clawlet");
        let keystore_dir = data_dir.join("keystore");
        std::fs::create_dir_all(&keystore_dir).unwrap();

        // 1. Generate a keystore
        let password = "integration-test-pw";
        let (address, ks_path) =
            clawlet_signer::keystore::Keystore::create(&keystore_dir, password).unwrap();

        assert!(ks_path.exists(), "keystore file should exist");
        assert_ne!(address.0, [0u8; 20], "address should not be zero");

        // 2. Verify unlock round-trip
        let key = clawlet_signer::keystore::Keystore::unlock(&ks_path, password).unwrap();
        let derived = clawlet_signer::keystore::public_key_to_address(&key);
        assert_eq!(address, derived);

        // 3. Write config.yaml
        let config_yaml = format!(
            r#"policy_path: "{policy}"
keystore_path: "{ks}"
audit_log_path: "{audit}"
"#,
            policy = data_dir.join("policy.yaml").display(),
            ks = keystore_dir.display(),
            audit = data_dir.join("audit.jsonl").display(),
        );
        let config_path = data_dir.join("config.yaml");
        std::fs::write(&config_path, &config_yaml).unwrap();

        // 4. Write policy.yaml
        let policy_yaml = r#"daily_transfer_limit_usd: 1000.0
per_tx_limit_usd: 500.0
allowed_tokens: []
allowed_chains: []
"#;
        let policy_path = data_dir.join("policy.yaml");
        std::fs::write(&policy_path, policy_yaml).unwrap();

        // 5. Verify parsing
        assert!(config_path.exists());
        assert!(policy_path.exists());

        let config = clawlet_core::config::Config::from_file(&config_path).unwrap();
        assert_eq!(config.rpc_bind, "127.0.0.1:9100");
        assert_eq!(config.keystore_path, keystore_dir);

        let policy = clawlet_core::policy::Policy::from_file(&policy_path).unwrap();
        assert_eq!(policy.daily_transfer_limit_usd, 1000.0);
        assert_eq!(policy.per_tx_limit_usd, 500.0);
    }

    // -----------------------------------------------------------------
    // test_balance_query — needs Anvil at http://127.0.0.1:8545
    // -----------------------------------------------------------------

    fn anvil_url() -> String {
        std::env::var("CLAWLET_ANVIL_URL").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string())
    }

    fn anvil_chain_id() -> u64 {
        std::env::var("CLAWLET_ANVIL_CHAIN_ID")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(31337)
    }

    #[test]
    #[ignore]
    fn test_balance_query() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let adapter = clawlet_evm::adapter::EvmAdapter::new(&anvil_url())
                .expect("should connect to Anvil");

            // Anvil default account 0
            let default_addr: alloy::primitives::Address =
                "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
                    .parse()
                    .unwrap();

            let balance = adapter.get_eth_balance(default_addr).await.unwrap();
            assert!(
                balance > alloy::primitives::U256::ZERO,
                "Anvil default account should have ETH"
            );

            let chain_id = adapter.get_chain_id().await.unwrap();
            assert_eq!(chain_id, anvil_chain_id(), "Anvil chain ID");
        });
    }

    // -----------------------------------------------------------------
    // test_transfer_with_policy — full flow on Anvil
    // -----------------------------------------------------------------

    #[test]
    #[ignore]
    fn test_transfer_with_policy() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // 1. Permissive policy
            let policy = Policy {
                daily_transfer_limit_usd: 100_000.0,
                per_tx_limit_usd: 50_000.0,
                allowed_tokens: vec!["ETH".to_string()],
                allowed_chains: vec![31337],
                require_approval_above_usd: None,
            };
            let engine = PolicyEngine::new(policy);

            let decision = engine.check_transfer(10.0, "ETH", 31337).unwrap();
            assert_eq!(decision, PolicyDecision::Allowed);

            // 2. Import Anvil's default key
            let tmp = tempfile::tempdir().unwrap();
            let anvil_key_hex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
            let private_key = hex::decode(anvil_key_hex).unwrap();
            let (_address, ks_path) = clawlet_signer::keystore::Keystore::create_from_key(
                tmp.path(),
                "test",
                &private_key,
            )
            .unwrap();

            // 3. Sign and send
            let signing_key = clawlet_signer::keystore::Keystore::unlock(&ks_path, "test").unwrap();
            let signer = clawlet_signer::signer::LocalSigner::new(signing_key);

            let adapter = clawlet_evm::adapter::EvmAdapter::new(&anvil_url()).unwrap();

            let recipient: alloy::primitives::Address =
                "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
                    .parse()
                    .unwrap();

            let tx_req = clawlet_evm::tx::TransferRequest {
                to: recipient,
                value: alloy::primitives::U256::from(1_000_000_000_000_000u64), // 0.001 ETH
                chain_id: 31337,
                gas_limit: Some(21000),
            };
            let tx = clawlet_evm::tx::build_eth_transfer(&tx_req);

            let tx_hash = clawlet_evm::tx::send_transaction(&adapter, &signer, tx)
                .await
                .expect("transfer should succeed on Anvil");

            assert_ne!(tx_hash, alloy::primitives::B256::ZERO);
        });
    }

    // -----------------------------------------------------------------
    // test_transfer_denied_by_policy — no Anvil needed
    // -----------------------------------------------------------------

    #[test]
    fn test_transfer_denied_by_policy() {
        // Per-tx limit exceeded
        let policy = Policy {
            daily_transfer_limit_usd: 1000.0,
            per_tx_limit_usd: 100.0,
            allowed_tokens: vec![],
            allowed_chains: vec![],
            require_approval_above_usd: None,
        };
        let engine = PolicyEngine::new(policy);
        let decision = engine.check_transfer(200.0, "ETH", 1).unwrap();
        assert!(
            matches!(decision, PolicyDecision::Denied(_)),
            "should be denied: exceeds per-tx limit"
        );

        // Daily limit exceeded
        let engine2 = PolicyEngine::new(Policy {
            daily_transfer_limit_usd: 150.0,
            per_tx_limit_usd: 100.0,
            allowed_tokens: vec![],
            allowed_chains: vec![],
            require_approval_above_usd: None,
        });
        assert_eq!(
            engine2.check_transfer(90.0, "ETH", 1).unwrap(),
            PolicyDecision::Allowed
        );
        let decision2 = engine2.check_transfer(90.0, "ETH", 1).unwrap();
        assert!(
            matches!(decision2, PolicyDecision::Denied(_)),
            "should be denied: daily limit exceeded"
        );
    }

    // -----------------------------------------------------------------
    // test_audit_log_written — verifies audit JSONL output
    // -----------------------------------------------------------------

    #[test]
    fn test_audit_log_written() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("audit.jsonl");

        {
            let mut logger = AuditLogger::new(&log_path).unwrap();

            logger
                .log_event(AuditEvent::new(
                    "policy_check",
                    json!({"amount_usd": 50.0, "token": "ETH", "chain_id": 1}),
                    "allowed",
                ))
                .unwrap();

            logger
                .log_event(AuditEvent::new(
                    "transfer",
                    json!({"to": "0x7099…", "value_wei": "1000000000000000", "chain_id": 1}),
                    "submitted",
                ))
                .unwrap();

            logger
                .log_event(AuditEvent::new(
                    "policy_check",
                    json!({"amount_usd": 9999.0, "token": "ETH", "chain_id": 1}),
                    "denied",
                ))
                .unwrap();
        }

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(lines.len(), 3, "should have 3 audit entries");

        let events: Vec<serde_json::Value> = lines
            .iter()
            .map(|line| serde_json::from_str(line).expect("valid JSON"))
            .collect();

        assert_eq!(events[0]["event_type"], "policy_check");
        assert_eq!(events[0]["outcome"], "allowed");
        assert_eq!(events[1]["event_type"], "transfer");
        assert_eq!(events[1]["outcome"], "submitted");
        assert_eq!(events[2]["event_type"], "policy_check");
        assert_eq!(events[2]["outcome"], "denied");

        for event in &events {
            assert!(event.get("timestamp").is_some());
        }
    }
}
