//! Integration tests for Clawlet.
//!
//! Anvil-dependent tests use **testcontainers** to spin up a Docker-based
//! Anvil node automatically — no manual `anvil &` needed.
//!
//! ```bash
//! # Run everything (Docker must be available):
//! cargo test -p clawlet-integration-tests -- --include-ignored
//! ```

#[cfg(test)]
mod tests {
    use alloy::dyn_abi::{DynSolType, DynSolValue, JsonAbiExt};
    use alloy::json_abi::Function;
    use alloy::network::TransactionBuilder;
    use alloy::primitives::{Address, Bytes, B256, U256};
    use alloy::providers::Provider;
    use alloy::rpc::types::TransactionRequest;
    use clawlet_core::ais::AisSpec;
    use clawlet_core::audit::{AuditEvent, AuditLogger};
    use clawlet_core::policy::{Policy, PolicyDecision, PolicyEngine};
    use clawlet_evm::adapter::EvmAdapter;
    use clawlet_evm::executor;
    use clawlet_evm::tx;
    use clawlet_signer::signer::LocalSigner;
    use clawlet_signer::signer::Signer;
    use serde_json::json;
    use testcontainers::{
        core::{IntoContainerPort, WaitFor},
        runners::SyncRunner,
        Container, GenericImage, ImageExt,
    };

    /// Spins up a Docker Anvil container and returns `(container, rpc_url)`.
    /// The container is dropped (and removed) when it goes out of scope.
    fn start_anvil() -> (Container<GenericImage>, String) {
        let image = GenericImage::new("ghcr.io/foundry-rs/foundry", "latest")
            .with_exposed_port(8545.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Listening on"))
            .with_entrypoint("anvil")
            .with_cmd(vec![
                "--host".to_string(),
                "0.0.0.0".to_string(),
                "--port".to_string(),
                "8545".to_string(),
                "--chain-id".to_string(),
                "31337".to_string(),
            ]);

        let container = image.start().expect("Docker must be available to run Anvil tests");
        let host_port = container.get_host_port_ipv4(8545).expect("failed to get mapped port");
        let url = format!("http://127.0.0.1:{}", host_port);
        (container, url)
    }

    fn skills_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("skills")
    }

    fn load_skill(name: &str) -> AisSpec {
        let path = skills_dir().join(format!("{name}.yaml"));
        AisSpec::from_file(&path).expect("failed to load AIS spec")
    }

    fn env_anvil() -> Option<(String, [u8; 32])> {
        let url = std::env::var("ANVIL_URL").ok()?;
        let key_hex = std::env::var("ANVIL_PRIVATE_KEY").ok()?;
        let bytes = hex::decode(key_hex.trim_start_matches("0x")).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Some((url, key))
    }

    async fn wait_for_receipt(adapter: &EvmAdapter, tx_hash: B256) -> Option<()> {
        for _ in 0..10 {
            let receipt = adapter.provider().get_transaction_receipt(tx_hash).await.ok()?;
            if receipt.is_some() {
                return Some(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        None
    }

    async fn deposit_weth(
        adapter: &EvmAdapter,
        signer: &LocalSigner,
        amount: U256,
    ) -> B256 {
        let weth: Address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
            .parse()
            .unwrap();
        let func = Function::parse("deposit()").unwrap();
        let data = func.abi_encode_input(&[]).unwrap();

        let mut tx_req = TransactionRequest::default()
            .to(weth)
            .value(amount)
            .input(Bytes::from(data).into());
        let chain_id = adapter.get_chain_id().await.unwrap_or(1);
        tx_req.set_chain_id(chain_id);

        let tx_hash = tx::send_transaction(adapter, signer, tx_req).await.unwrap();
        let _ = wait_for_receipt(adapter, tx_hash).await;
        tx_hash
    }

    async fn execute_uniswap_swap(
        adapter: &EvmAdapter,
        signer: &LocalSigner,
        amount_in: U256,
        min_amount_out: U256,
    ) {
        let spec = load_skill("uniswap_v3_swap");
        let weth: Address = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
            .parse()
            .unwrap();
        let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            .parse()
            .unwrap();
        let owner = clawlet_evm::adapter::core_address_to_alloy(&signer.address());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut params = std::collections::HashMap::new();
        params.insert("token_in".to_string(), weth.to_string());
        params.insert("token_out".to_string(), usdc.to_string());
        params.insert("amount_in".to_string(), amount_in.to_string());
        params.insert("min_amount_out".to_string(), min_amount_out.to_string());
        params.insert("recipient".to_string(), owner.to_string());
        params.insert("deadline".to_string(), (now + 600).to_string());

        let _ = executor::execute_spec(&spec, params, adapter, signer)
            .await
            .unwrap();
    }

    async fn aave_a_token_address(
        adapter: &EvmAdapter,
        pool: Address,
        asset: Address,
    ) -> Address {
        let func = Function::parse("getReserveData(address)").unwrap();
        let data = func
            .abi_encode_input(&[DynSolValue::Address(asset)])
            .unwrap();
        let result: Bytes = adapter
            .provider()
            .call(TransactionRequest::default().to(pool).input(data.into()))
            .await
            .unwrap();

        let types = DynSolType::Tuple(vec![
            DynSolType::Uint(256),
            DynSolType::Uint(128),
            DynSolType::Uint(128),
            DynSolType::Uint(128),
            DynSolType::Uint(128),
            DynSolType::Uint(128),
            DynSolType::Uint(40),
            DynSolType::Address,
            DynSolType::Address,
            DynSolType::Address,
            DynSolType::Address,
            DynSolType::Uint(8),
        ]);
        let decoded = types.abi_decode(&result).unwrap();
        match decoded {
            DynSolValue::Tuple(values) => match values.get(7) {
                Some(DynSolValue::Address(addr)) => *addr,
                _ => Address::ZERO,
            },
            _ => Address::ZERO,
        }
    }

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
    // test_balance_query — Anvil via testcontainers
    // -----------------------------------------------------------------

    #[test]
    #[ignore]
    fn test_balance_query() {
        let (_anvil, anvil_url) = start_anvil();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let adapter = clawlet_evm::adapter::EvmAdapter::new(&anvil_url)
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
            assert_eq!(chain_id, 31337, "Anvil default chain ID");
        });
    }

    // -----------------------------------------------------------------
    // test_transfer_with_policy — full flow on Anvil via testcontainers
    // -----------------------------------------------------------------

    #[test]
    #[ignore]
    fn test_transfer_with_policy() {
        let (_anvil, anvil_url) = start_anvil();

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
            let anvil_key_hex =
                "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
            let private_key = hex::decode(anvil_key_hex).unwrap();
            let (_address, ks_path) = clawlet_signer::keystore::Keystore::create_from_key(
                tmp.path(),
                "test",
                &private_key,
            )
            .unwrap();

            // 3. Sign and send
            let signing_key =
                clawlet_signer::keystore::Keystore::unlock(&ks_path, "test").unwrap();
            let signer = clawlet_signer::signer::LocalSigner::new(signing_key);

            let adapter = clawlet_evm::adapter::EvmAdapter::new(&anvil_url).unwrap();

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

    // -----------------------------------------------------------------
    // test_uniswap_v3_swap_ais — mainnet fork via ANVIL_URL
    // -----------------------------------------------------------------

    #[test]
    #[ignore]
    fn test_uniswap_v3_swap_ais() {
        let Some((anvil_url, private_key)) = env_anvil() else {
            eprintln!("skipping: set ANVIL_URL and ANVIL_PRIVATE_KEY to run");
            return;
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let adapter = EvmAdapter::new(&anvil_url).expect("should connect to Anvil fork");
            let signer = LocalSigner::from_bytes(&private_key).unwrap();
            let owner = clawlet_evm::adapter::core_address_to_alloy(&signer.address());

            let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
                .parse()
                .unwrap();
            let amount_in = U256::from(1_000_000_000_000_000u64); // 0.001 WETH

            let usdc_before = adapter.get_erc20_balance(usdc, owner).await.unwrap();
            let _ = deposit_weth(&adapter, &signer, amount_in).await;
            execute_uniswap_swap(&adapter, &signer, amount_in, U256::from(1u64)).await;
            let usdc_after = adapter.get_erc20_balance(usdc, owner).await.unwrap();

            assert!(
                usdc_after > usdc_before,
                "USDC balance should increase after swap"
            );
        });
    }

    // -----------------------------------------------------------------
    // test_aave_v3_supply_withdraw_ais — mainnet fork via ANVIL_URL
    // -----------------------------------------------------------------

    #[test]
    #[ignore]
    fn test_aave_v3_supply_withdraw_ais() {
        let Some((anvil_url, private_key)) = env_anvil() else {
            eprintln!("skipping: set ANVIL_URL and ANVIL_PRIVATE_KEY to run");
            return;
        };

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let adapter = EvmAdapter::new(&anvil_url).expect("should connect to Anvil fork");
            let signer = LocalSigner::from_bytes(&private_key).unwrap();
            let owner = clawlet_evm::adapter::core_address_to_alloy(&signer.address());

            let usdc: Address = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
                .parse()
                .unwrap();
            let pool: Address = "0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2"
                .parse()
                .unwrap();

            let usdc_before = adapter.get_erc20_balance(usdc, owner).await.unwrap();
            let amount = U256::from(1_000_000u64); // 1 USDC

            if usdc_before < amount {
                let weth_amount = U256::from(2_000_000_000_000_000u64); // 0.002 WETH
                let _ = deposit_weth(&adapter, &signer, weth_amount).await;
                execute_uniswap_swap(&adapter, &signer, weth_amount, U256::from(1u64)).await;
            }

            let usdc_mid = adapter.get_erc20_balance(usdc, owner).await.unwrap();
            assert!(usdc_mid >= amount, "expected USDC balance for supply");

            let a_token = aave_a_token_address(&adapter, pool, usdc).await;
            let a_before = adapter.get_erc20_balance(a_token, owner).await.unwrap();

            let supply = load_skill("aave_v3_supply");
            let mut supply_params = std::collections::HashMap::new();
            supply_params.insert("asset".to_string(), usdc.to_string());
            supply_params.insert("amount".to_string(), amount.to_string());
            supply_params.insert("on_behalf".to_string(), owner.to_string());
            supply_params.insert("referral_code".to_string(), "0".to_string());
            supply_params.insert("pool_address".to_string(), pool.to_string());

            let _ = executor::execute_spec(&supply, supply_params, &adapter, &signer)
                .await
                .unwrap();

            let a_after = adapter.get_erc20_balance(a_token, owner).await.unwrap();
            let usdc_after_supply = adapter.get_erc20_balance(usdc, owner).await.unwrap();
            assert!(a_after > a_before, "aToken balance should increase");
            assert!(usdc_after_supply < usdc_mid, "USDC balance should decrease");

            let withdraw = load_skill("aave_v3_withdraw");
            let mut withdraw_params = std::collections::HashMap::new();
            withdraw_params.insert("asset".to_string(), usdc.to_string());
            withdraw_params.insert("amount".to_string(), amount.to_string());
            withdraw_params.insert("recipient".to_string(), owner.to_string());
            withdraw_params.insert("pool_address".to_string(), pool.to_string());

            let _ = executor::execute_spec(&withdraw, withdraw_params, &adapter, &signer)
                .await
                .unwrap();

            let a_final = adapter.get_erc20_balance(a_token, owner).await.unwrap();
            let usdc_final = adapter.get_erc20_balance(usdc, owner).await.unwrap();
            assert!(a_final < a_after, "aToken balance should decrease");
            assert!(usdc_final >= usdc_after_supply, "USDC balance should recover");
        });
    }
}
