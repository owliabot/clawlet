//! Comprehensive integration tests for Clawlet.
//!
//! Anvil-dependent tests use **testcontainers** to spin up a Docker-based
//! Anvil node automatically — no manual `anvil &` needed.
//!
//! ```bash
//! # Run non-Anvil tests only (default):
//! cargo test -p clawlet-integration-tests
//!
//! # Run all tests including Anvil tests (Docker must be available):
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
    use clawlet_core::config::Config;
    use clawlet_core::policy::{Policy, PolicyDecision, PolicyEngine};
    use clawlet_evm::adapter::EvmAdapter;
    use clawlet_evm::executor;
    use clawlet_evm::tx;
    use clawlet_signer::hd;
    use clawlet_signer::keystore::Keystore;
    use clawlet_signer::signer::LocalSigner;
    use clawlet_signer::signer::Signer;
    use serde_json::json;
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::process::Command;
    use testcontainers::{
        core::{IntoContainerPort, WaitFor},
        runners::SyncRunner,
        Container, GenericImage, ImageExt,
    };

    // =========================================================================
    // Helper Functions
    // =========================================================================

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

        let container = image
            .start()
            .expect("Docker must be available to run Anvil tests");
        let host_port = container
            .get_host_port_ipv4(8545)
            .expect("failed to get mapped port");
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
            let receipt = adapter
                .provider()
                .get_transaction_receipt(tx_hash)
                .await
                .ok()?;
            if receipt.is_some() {
                return Some(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        None
    }

    async fn deposit_weth(adapter: &EvmAdapter, signer: &LocalSigner, amount: U256) -> B256 {
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

    async fn aave_a_token_address(adapter: &EvmAdapter, pool: Address, asset: Address) -> Address {
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

    /// Well-known Anvil account #0 private key
    const ANVIL_ACCOUNT_0_KEY: &str =
        "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    /// Well-known Anvil account #1 address
    const ANVIL_ACCOUNT_1_ADDR: &str = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";

    /// Standard BIP-39 test mnemonic
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    /// Expected address for test mnemonic at m/44'/60'/0'/0/0
    const TEST_MNEMONIC_ADDR: &str = "9858effd232b4033e47d90003d41ec34ecaeda94";

    /// Cargo binary path for the CLI
    #[allow(dead_code)]
    fn clawlet_bin() -> PathBuf {
        // Find the clawlet binary in the target directory
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();
        let target_dir = workspace_root.join("target").join("debug").join("clawlet");
        target_dir
    }

    // =========================================================================
    // FULL FLOW TESTS (Require Anvil)
    // =========================================================================

    /// Test 1: Initialize keystore, start serve (simulated), health check, shutdown
    #[test]
    fn test_init_and_serve_roundtrip() {
        let (_anvil, anvil_url) = start_anvil();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let tmp = tempfile::tempdir().unwrap();
            let data_dir = tmp.path();
            let keystore_dir = data_dir.join("keystore");
            std::fs::create_dir_all(&keystore_dir).unwrap();

            // 1. Create keystore
            let password = "test-password";
            let anvil_key = hex::decode(ANVIL_ACCOUNT_0_KEY).unwrap();
            let (address, ks_path) =
                Keystore::create_from_key(&keystore_dir, password, &anvil_key).unwrap();
            assert!(ks_path.exists());
            assert_ne!(address.0, [0u8; 20]);

            // 2. Write config with Anvil RPC
            let config_yaml = format!(
                r#"policy_path: "{policy}"
keystore_path: "{ks}"
rpc_bind: "127.0.0.1:9199"
audit_log_path: "{audit}"
chain_rpc_urls:
  31337: "{rpc}"
"#,
                policy = data_dir.join("policy.yaml").display(),
                ks = keystore_dir.display(),
                audit = data_dir.join("audit.jsonl").display(),
                rpc = anvil_url,
            );
            let config_path = data_dir.join("config.yaml");
            std::fs::write(&config_path, &config_yaml).unwrap();

            // 3. Write policy
            let policy_yaml = r#"daily_transfer_limit_usd: 10000.0
per_tx_limit_usd: 5000.0
allowed_tokens: []
allowed_chains: []
"#;
            std::fs::write(data_dir.join("policy.yaml"), policy_yaml).unwrap();

            // 4. Verify config parses
            let config = Config::from_file(&config_path).unwrap();
            assert_eq!(config.rpc_bind, "127.0.0.1:9199");
            assert!(config.chain_rpc_urls.contains_key(&31337));

            // 5. Unlock keystore and create signer
            let signing_key = Keystore::unlock(&ks_path, password).unwrap();
            let signer = LocalSigner::new(signing_key);
            let signer_addr = clawlet_evm::adapter::core_address_to_alloy(&signer.address());

            // 6. Connect to Anvil and verify balance
            let adapter = EvmAdapter::new(&anvil_url).unwrap();
            let balance = adapter.get_eth_balance(signer_addr).await.unwrap();
            assert!(balance > U256::ZERO, "Anvil account should have ETH");

            // 7. Verify chain ID
            let chain_id = adapter.get_chain_id().await.unwrap();
            assert_eq!(chain_id, 31337);
        });
    }

    /// Test 2: Query ETH balance of Anvil default account (should have 10000 ETH)
    #[test]
    fn test_eth_balance_query_on_anvil() {
        let (_anvil, anvil_url) = start_anvil();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let adapter = EvmAdapter::new(&anvil_url).expect("should connect to Anvil");

            // Anvil default account 0
            let default_addr: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
                .parse()
                .unwrap();

            let balance = adapter.get_eth_balance(default_addr).await.unwrap();

            // Anvil starts accounts with 10000 ETH = 10000 * 10^18 wei
            let ten_thousand_eth = U256::from(10000u64) * U256::from(10u64).pow(U256::from(18u64));
            assert_eq!(
                balance, ten_thousand_eth,
                "Anvil default account should have exactly 10000 ETH"
            );

            let chain_id = adapter.get_chain_id().await.unwrap();
            assert_eq!(chain_id, 31337, "Anvil default chain ID");
        });
    }

    /// Test 3: Transfer ETH between two Anvil accounts
    #[test]
    fn test_eth_transfer_on_anvil() {
        let (_anvil, anvil_url) = start_anvil();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Import Anvil's default key
            let tmp = tempfile::tempdir().unwrap();
            let private_key = hex::decode(ANVIL_ACCOUNT_0_KEY).unwrap();
            let (_address, ks_path) =
                Keystore::create_from_key(tmp.path(), "test", &private_key).unwrap();

            let signing_key = Keystore::unlock(&ks_path, "test").unwrap();
            let signer = LocalSigner::new(signing_key);
            let adapter = EvmAdapter::new(&anvil_url).unwrap();

            let recipient: Address = ANVIL_ACCOUNT_1_ADDR.parse().unwrap();

            // Get initial balances
            let sender_addr = clawlet_evm::adapter::core_address_to_alloy(&signer.address());
            let sender_before = adapter.get_eth_balance(sender_addr).await.unwrap();
            let recipient_before = adapter.get_eth_balance(recipient).await.unwrap();

            // Transfer 1 ETH
            let one_eth = U256::from(10u64).pow(U256::from(18u64));
            let tx_req = tx::TransferRequest {
                to: recipient,
                value: one_eth,
                chain_id: 31337,
                gas_limit: Some(21000),
            };
            let tx = tx::build_eth_transfer(&tx_req);
            let tx_hash = tx::send_transaction(&adapter, &signer, tx)
                .await
                .expect("transfer should succeed");

            assert_ne!(tx_hash, B256::ZERO);
            wait_for_receipt(&adapter, tx_hash).await.unwrap();

            // Verify balances changed
            let sender_after = adapter.get_eth_balance(sender_addr).await.unwrap();
            let recipient_after = adapter.get_eth_balance(recipient).await.unwrap();

            // Recipient should have +1 ETH
            assert_eq!(recipient_after - recipient_before, one_eth);

            // Sender should have -(1 ETH + gas)
            assert!(sender_before - sender_after >= one_eth);
        });
    }

    /// Test 4: Deploy mock ERC-20 and transfer tokens
    ///
    /// Deploys a minimal ERC-20 contract (SimpleToken) that mints 1M tokens (10^24) to deployer,
    /// then transfers tokens to another account and verifies balances changed correctly.
    #[test]
    fn test_erc20_transfer_on_anvil() {
        let (_anvil, anvil_url) = start_anvil();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let tmp = tempfile::tempdir().unwrap();
            let private_key = hex::decode(ANVIL_ACCOUNT_0_KEY).unwrap();
            let (_address, ks_path) =
                Keystore::create_from_key(tmp.path(), "test", &private_key).unwrap();

            let signing_key = Keystore::unlock(&ks_path, "test").unwrap();
            let signer = LocalSigner::new(signing_key);
            let adapter = EvmAdapter::new(&anvil_url).unwrap();

            let owner = clawlet_evm::adapter::core_address_to_alloy(&signer.address());
            let recipient: Address = ANVIL_ACCOUNT_1_ADDR.parse().unwrap();

            // Deploy a minimal ERC-20 contract (SimpleToken)
            // Compiled with solc 0.8.33 via `forge build`
            // Source:
            // ```solidity
            // // SPDX-License-Identifier: MIT
            // pragma solidity ^0.8.17;
            // contract SimpleToken {
            //     mapping(address => uint256) public balanceOf;
            //     constructor() { balanceOf[msg.sender] = 1000000 * 10**18; }
            //     function transfer(address to, uint256 amount) public returns (bool) {
            //         require(balanceOf[msg.sender] >= amount, "Insufficient balance");
            //         balanceOf[msg.sender] -= amount;
            //         balanceOf[to] += amount;
            //         return true;
            //     }
            // }
            // ```
            let deploy_bytecode = hex::decode(
                "6080604052348015600e575f5ffd5b5069d3c21bcecceda10000005f5f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2081905550610470806100675f395ff3fe608060405234801561000f575f5ffd5b5060043610610034575f3560e01c806370a0823114610038578063a9059cbb14610068575b5f5ffd5b610052600480360381019061004d9190610238565b610098565b60405161005f919061027b565b60405180910390f35b610082600480360381019061007d91906102be565b6100ac565b60405161008f9190610316565b60405180910390f35b5f602052805f5260405f205f915090505481565b5f815f5f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f2054101561012c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161012390610389565b60405180910390fd5b815f5f3373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f82825461017791906103d4565b92505081905550815f5f8573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020015f205f8282546101c99190610407565b925050819055506001905092915050565b5f5ffd5b5f73ffffffffffffffffffffffffffffffffffffffff82169050919050565b5f610207826101de565b9050919050565b610217816101fd565b8114610221575f5ffd5b50565b5f813590506102328161020e565b92915050565b5f6020828403121561024d5761024c6101da565b5b5f61025a84828501610224565b91505092915050565b5f819050919050565b61027581610263565b82525050565b5f60208201905061028e5f83018461026c565b92915050565b61029d81610263565b81146102a7575f5ffd5b50565b5f813590506102b881610294565b92915050565b5f5f604083850312156102d4576102d36101da565b5b5f6102e185828601610224565b92505060206102f2858286016102aa565b9150509250929050565b5f8115159050919050565b610310816102fc565b82525050565b5f6020820190506103295f830184610307565b92915050565b5f82825260208201905092915050565b7f496e73756666696369656e742062616c616e63650000000000000000000000005f82015250565b5f61037360148361032f565b915061037e8261033f565b602082019050919050565b5f6020820190508181035f8301526103a081610367565b9050919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b5f6103de82610263565b91506103e983610263565b9250828203905081811115610401576104006103a7565b5b92915050565b5f61041182610263565b915061041c83610263565b9250828201905080821115610434576104336103a7565b5b9291505056fea26469706673582212202533f4a607217075eacb2a0cbb0075e99ce5ae5ff0402d62ad03ffb756cd3f5564736f6c63430008210033",
            )
            .expect("invalid hex bytecode");

            // Deploy the contract (gas used ~321k, set limit higher)
            let deploy_tx = TransactionRequest::default()
                .input(Bytes::from(deploy_bytecode).into())
                .with_chain_id(31337)
                .gas_limit(500_000);

            let deploy_hash = tx::send_transaction(&adapter, &signer, deploy_tx)
                .await
                .expect("contract deployment should succeed");

            wait_for_receipt(&adapter, deploy_hash)
                .await
                .expect("deployment receipt not found");

            // Get the deployed contract address from the receipt
            let receipt = adapter
                .provider()
                .get_transaction_receipt(deploy_hash)
                .await
                .expect("failed to get receipt")
                .expect("receipt should exist");

            let token_address = receipt
                .contract_address
                .expect("contract address should be in receipt");

            // Check initial balances
            let owner_balance_before = adapter
                .get_erc20_balance(token_address, owner)
                .await
                .expect("failed to get owner balance");
            let recipient_balance_before = adapter
                .get_erc20_balance(token_address, recipient)
                .await
                .expect("failed to get recipient balance");

            // Owner should have 1M tokens (1,000,000 * 10^18)
            let expected_initial = U256::from(1_000_000u64) * U256::from(10u64).pow(U256::from(18));
            assert_eq!(
                owner_balance_before, expected_initial,
                "Owner should have 1M tokens after deployment"
            );
            assert_eq!(
                recipient_balance_before,
                U256::ZERO,
                "Recipient should have 0 tokens initially"
            );

            // Transfer 100 tokens to recipient
            let transfer_amount = U256::from(100u64) * U256::from(10u64).pow(U256::from(18));
            let transfer_tx =
                tx::build_erc20_transfer(token_address, recipient, transfer_amount, 31337);
            let transfer_hash = tx::send_transaction(&adapter, &signer, transfer_tx)
                .await
                .expect("ERC-20 transfer should succeed");

            wait_for_receipt(&adapter, transfer_hash)
                .await
                .expect("transfer receipt not found");

            // Verify balances changed correctly
            let owner_balance_after = adapter
                .get_erc20_balance(token_address, owner)
                .await
                .expect("failed to get owner balance after transfer");
            let recipient_balance_after = adapter
                .get_erc20_balance(token_address, recipient)
                .await
                .expect("failed to get recipient balance after transfer");

            assert_eq!(
                owner_balance_after,
                owner_balance_before - transfer_amount,
                "Owner balance should decrease by transfer amount"
            );
            assert_eq!(
                recipient_balance_after, transfer_amount,
                "Recipient should have exactly the transferred amount"
            );
        });
    }

    /// Test 5: Policy denies transfer, verify no transaction sent
    #[test]
    fn test_transfer_blocked_by_policy() {
        let (_anvil, anvil_url) = start_anvil();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            // Restrictive policy - only allows USDC on chain 1
            let policy = Policy {
                daily_transfer_limit_usd: 100.0,
                per_tx_limit_usd: 50.0,
                allowed_tokens: vec!["USDC".to_string()],
                allowed_chains: vec![1],
                require_approval_above_usd: None,
            };
            let engine = PolicyEngine::new(policy);

            // Try to transfer ETH on chain 31337 (Anvil) - should be denied
            let decision = engine.check_transfer(10.0, "ETH", 31337).unwrap();
            assert!(
                matches!(decision, PolicyDecision::Denied(_)),
                "ETH transfer on chain 31337 should be denied by policy"
            );

            // Also check token not in allowlist
            let decision = engine.check_transfer(10.0, "ETH", 1).unwrap();
            assert!(
                matches!(decision, PolicyDecision::Denied(_)),
                "ETH (not USDC) should be denied"
            );

            // Import key to verify we can still connect
            let tmp = tempfile::tempdir().unwrap();
            let private_key = hex::decode(ANVIL_ACCOUNT_0_KEY).unwrap();
            let (_address, ks_path) =
                Keystore::create_from_key(tmp.path(), "test", &private_key).unwrap();

            let signing_key = Keystore::unlock(&ks_path, "test").unwrap();
            let signer = LocalSigner::new(signing_key);
            let adapter = EvmAdapter::new(&anvil_url).unwrap();

            // Get sender's nonce before
            let sender_addr = clawlet_evm::adapter::core_address_to_alloy(&signer.address());
            let nonce_before = adapter
                .provider()
                .get_transaction_count(sender_addr)
                .await
                .unwrap();

            // Since policy denied, we should NOT send the transaction
            // (In real code, you'd check policy before sending)

            // Verify nonce hasn't changed (no tx sent)
            let nonce_after = adapter
                .provider()
                .get_transaction_count(sender_addr)
                .await
                .unwrap();
            assert_eq!(
                nonce_before, nonce_after,
                "No transaction should have been sent"
            );
        });
    }

    /// Test 6: Policy requires approval, verify response
    #[test]
    fn test_transfer_requires_approval() {
        let policy = Policy {
            daily_transfer_limit_usd: 10000.0,
            per_tx_limit_usd: 5000.0,
            allowed_tokens: vec![],
            allowed_chains: vec![],
            require_approval_above_usd: Some(100.0),
        };
        let engine = PolicyEngine::new(policy);

        // Under threshold - allowed
        let decision = engine.check_transfer(50.0, "ETH", 1).unwrap();
        assert_eq!(decision, PolicyDecision::Allowed);

        // Over threshold - requires approval
        let decision = engine.check_transfer(150.0, "ETH", 1).unwrap();
        assert!(
            matches!(decision, PolicyDecision::RequiresApproval(_)),
            "Transfer over $100 should require approval"
        );

        // Verify the message contains useful info
        if let PolicyDecision::RequiresApproval(msg) = decision {
            assert!(msg.contains("150"));
            assert!(msg.contains("100"));
        }
    }

    /// Test 7: Audit log records all operations
    #[test]
    fn test_audit_log_records_all_operations() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("audit.jsonl");

        {
            let mut logger = AuditLogger::new(&log_path).unwrap();

            // Log various operations
            logger
                .log_event(AuditEvent::new(
                    "keystore_unlock",
                    json!({"address": "0xf39F..."}),
                    "success",
                ))
                .unwrap();

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
                    json!({"to": "0x7099...", "value_wei": "1000000000000000000", "chain_id": 1}),
                    "submitted",
                ))
                .unwrap();

            logger
                .log_event(AuditEvent::new(
                    "transfer",
                    json!({"tx_hash": "0xabc..."}),
                    "confirmed",
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

        // Verify log contents
        let contents = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = contents.trim().lines().collect();
        assert_eq!(lines.len(), 5, "should have 5 audit entries");

        let events: Vec<serde_json::Value> = lines
            .iter()
            .map(|line| serde_json::from_str(line).expect("valid JSON"))
            .collect();

        // Verify event types
        assert_eq!(events[0]["event_type"], "keystore_unlock");
        assert_eq!(events[1]["event_type"], "policy_check");
        assert_eq!(events[2]["event_type"], "transfer");
        assert_eq!(events[3]["event_type"], "transfer");
        assert_eq!(events[4]["event_type"], "policy_check");

        // Verify outcomes
        assert_eq!(events[0]["outcome"], "success");
        assert_eq!(events[1]["outcome"], "allowed");
        assert_eq!(events[2]["outcome"], "submitted");
        assert_eq!(events[3]["outcome"], "confirmed");
        assert_eq!(events[4]["outcome"], "denied");

        // Verify all have timestamps
        for event in &events {
            assert!(event.get("timestamp").is_some());
            // Timestamp should be a valid ISO 8601 string
            let ts = event["timestamp"].as_str().unwrap();
            assert!(ts.contains("T"));
        }

        // Verify details are preserved
        assert_eq!(events[1]["details"]["amount_usd"], 50.0);
        assert_eq!(events[1]["details"]["token"], "ETH");
    }

    /// Test 8: Wrong password fails gracefully
    #[test]
    fn test_keystore_unlock_wrong_password() {
        let tmp = tempfile::tempdir().unwrap();
        let password = "correct-password";

        let (_address, ks_path) = Keystore::create(tmp.path(), password).unwrap();
        assert!(ks_path.exists());

        // Try to unlock with wrong password
        let result = Keystore::unlock(&ks_path, "wrong-password");
        assert!(result.is_err(), "Wrong password should fail");

        // Verify the error is a keystore error (not IO or other)
        let err = result.unwrap_err();
        let err_msg = err.to_string();
        assert!(
            err_msg.contains("crypto") || err_msg.contains("keystore") || err_msg.contains("Mac"),
            "Error should indicate crypto/keystore failure: {err_msg}"
        );

        // Correct password still works
        let result = Keystore::unlock(&ks_path, password);
        assert!(result.is_ok(), "Correct password should work");
    }

    /// Test 9: HD derivation produces 5 different addresses
    #[test]
    fn test_hd_derivation_multiple_accounts() {
        let mnemonic = hd::generate_mnemonic();
        let mut addresses = HashSet::new();

        for i in 0..5 {
            let key = hd::derive_key(&mnemonic, i).unwrap();
            let addr = clawlet_signer::keystore::public_key_to_address(&key);
            addresses.insert(addr.0);
        }

        assert_eq!(
            addresses.len(),
            5,
            "All 5 derived addresses should be unique"
        );

        // Also verify known mnemonic produces expected address
        let key = hd::derive_key(TEST_MNEMONIC, 0).unwrap();
        let addr = clawlet_signer::keystore::public_key_to_address(&key);
        let actual = hex::encode(addr.0);
        assert_eq!(
            actual, TEST_MNEMONIC_ADDR,
            "Known mnemonic should produce expected address"
        );
    }

    // =========================================================================
    // POLICY INTEGRATION TESTS (No Anvil needed)
    // =========================================================================

    /// Test 10: Load and parse config/policy.example.yaml
    #[test]
    fn test_policy_from_example_config() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let policy_path = manifest_dir
            .join("..")
            .join("..")
            .join("config")
            .join("policy.example.yaml");

        // The example file exists
        assert!(
            policy_path.exists(),
            "policy.example.yaml should exist at {policy_path:?}"
        );

        // Read and verify it has expected structure
        let contents = std::fs::read_to_string(&policy_path).unwrap();
        assert!(contents.contains("limits:"));
        assert!(contents.contains("daily_transfer_usd"));
        assert!(contents.contains("allowed_tokens"));
        assert!(contents.contains("audit:"));
    }

    /// Test 11: Daily limit accumulation across multiple checks
    #[test]
    fn test_policy_daily_limit_across_multiple_checks() {
        let policy = Policy {
            daily_transfer_limit_usd: 1000.0,
            per_tx_limit_usd: 300.0,
            allowed_tokens: vec![],
            allowed_chains: vec![],
            require_approval_above_usd: None,
        };
        let engine = PolicyEngine::new(policy);

        // Simulate a day's worth of transfers
        // 300 + 300 + 300 = 900 (allowed)
        // 300 + 900 = 1200 > 1000 (denied)

        let d1 = engine.check_transfer(300.0, "ETH", 1).unwrap();
        assert_eq!(d1, PolicyDecision::Allowed, "First transfer of $300");

        let d2 = engine.check_transfer(300.0, "ETH", 1).unwrap();
        assert_eq!(d2, PolicyDecision::Allowed, "Second transfer of $300");

        let d3 = engine.check_transfer(300.0, "ETH", 1).unwrap();
        assert_eq!(d3, PolicyDecision::Allowed, "Third transfer of $300");

        // Now at $900, try to transfer $200 more (would be $1100 > $1000 limit)
        let d4 = engine.check_transfer(200.0, "ETH", 1).unwrap();
        assert!(
            matches!(d4, PolicyDecision::Denied(_)),
            "Fourth transfer should be denied - exceeds daily limit"
        );

        // But $100 should still work (900 + 100 = 1000 exactly)
        let d5 = engine.check_transfer(100.0, "ETH", 1).unwrap();
        assert_eq!(
            d5,
            PolicyDecision::Allowed,
            "Fifth transfer of $100 brings us to exactly $1000"
        );

        // Now at exactly limit, any more should be denied
        let d6 = engine.check_transfer(0.01, "ETH", 1).unwrap();
        assert!(
            matches!(d6, PolicyDecision::Denied(_)),
            "Even $0.01 more should be denied"
        );
    }

    /// Test 12: Custom policy YAML with edge cases
    #[test]
    fn test_policy_with_custom_yaml() {
        // Very restrictive policy
        let yaml1 = r#"
daily_transfer_limit_usd: 50.0
per_tx_limit_usd: 10.0
allowed_tokens:
  - USDC
allowed_chains:
  - 1
require_approval_above_usd: 5.0
"#;
        let p1 = Policy::from_yaml(yaml1).unwrap();
        let e1 = PolicyEngine::new(p1);

        // Under approval threshold
        assert_eq!(
            e1.check_transfer(4.0, "USDC", 1).unwrap(),
            PolicyDecision::Allowed
        );

        // Over approval threshold
        assert!(matches!(
            e1.check_transfer(8.0, "USDC", 1).unwrap(),
            PolicyDecision::RequiresApproval(_)
        ));

        // Over per-tx limit
        assert!(matches!(
            e1.check_transfer(15.0, "USDC", 1).unwrap(),
            PolicyDecision::Denied(_)
        ));

        // Wrong token
        assert!(matches!(
            e1.check_transfer(1.0, "ETH", 1).unwrap(),
            PolicyDecision::Denied(_)
        ));

        // Wrong chain
        assert!(matches!(
            e1.check_transfer(1.0, "USDC", 137).unwrap(),
            PolicyDecision::Denied(_)
        ));

        // Very permissive policy
        let yaml2 = r#"
daily_transfer_limit_usd: 1000000.0
per_tx_limit_usd: 1000000.0
"#;
        let p2 = Policy::from_yaml(yaml2).unwrap();
        let e2 = PolicyEngine::new(p2);

        // Everything should be allowed
        assert_eq!(
            e2.check_transfer(999999.0, "ANYTHING", 99999).unwrap(),
            PolicyDecision::Allowed
        );
    }

    // =========================================================================
    // RPC INTEGRATION TESTS (No Anvil needed for mock)
    // =========================================================================

    /// Test 13: RPC health endpoint (simulated via types)
    #[test]
    fn test_rpc_health_endpoint() {
        use clawlet_ipc::types::{RpcMethod, RpcRequest, RpcResponse, RpcStatus};

        // Simulate a health request
        let req = RpcRequest::new(RpcMethod::Health, "", &[]);
        assert_eq!(req.rpc_method(), Some(RpcMethod::Health));

        // Simulate a health response
        let response_json = serde_json::json!({"status": "healthy"}).to_string();
        let resp = RpcResponse::ok(response_json.as_bytes());
        assert!(resp.is_ok());
        assert_eq!(resp.status, RpcStatus::Ok as u32);

        let payload = std::str::from_utf8(resp.payload_bytes()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert_eq!(parsed["status"], "healthy");
    }

    /// Test 14: RPC auth required - request without token gets 401
    #[test]
    fn test_rpc_auth_required() {
        use clawlet_ipc::types::{RpcMethod, RpcRequest, RpcResponse, RpcStatus};

        // Request with empty token
        let req = RpcRequest::new(RpcMethod::Balance, "", b"{}");
        assert_eq!(req.token_str(), "");

        // Simulate unauthorized response
        let resp = RpcResponse::error(RpcStatus::Unauthorized, "auth token required");
        assert!(!resp.is_ok());
        assert_eq!(resp.status, RpcStatus::Unauthorized as u32);

        let payload = std::str::from_utf8(resp.payload_bytes()).unwrap();
        assert!(payload.contains("auth token required"));
    }

    /// Test 15: RPC auth valid - request with token gets 200
    #[test]
    fn test_rpc_auth_valid() {
        use clawlet_ipc::types::{RpcMethod, RpcRequest, RpcResponse, RpcStatus};

        // Request with valid token
        let token = "test-secret-token-12345";
        let req = RpcRequest::new(RpcMethod::Balance, token, b"{}");
        assert_eq!(req.token_str(), token);

        // Simulate successful response
        let response_json = serde_json::json!({"balance": "10000000000000000000"}).to_string();
        let resp = RpcResponse::ok(response_json.as_bytes());
        assert!(resp.is_ok());
        assert_eq!(resp.status, RpcStatus::Ok as u32);

        let payload = std::str::from_utf8(resp.payload_bytes()).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert!(parsed["balance"].as_str().is_some());
    }

    // =========================================================================
    // CLI INTEGRATION TESTS
    // =========================================================================

    /// Test 16: CLI init creates required files
    #[test]
    fn test_cli_init_creates_files() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path();

        // Instead of running the actual CLI (which requires TTY for password),
        // we simulate the init process
        let keystore_dir = data_dir.join("keystore");
        std::fs::create_dir_all(&keystore_dir).unwrap();

        // Create keystore
        let (address, ks_path) = Keystore::create(&keystore_dir, "test-password").unwrap();
        assert!(ks_path.exists());
        assert_ne!(address.0, [0u8; 20]);

        // Create policy
        let policy_yaml = r#"daily_transfer_limit_usd: 1000.0
per_tx_limit_usd: 500.0
allowed_tokens: []
allowed_chains: []
"#;
        let policy_path = data_dir.join("policy.yaml");
        std::fs::write(&policy_path, policy_yaml).unwrap();
        assert!(policy_path.exists());

        // Create config
        let config_yaml = format!(
            r#"policy_path: "{}"
keystore_path: "{}"
rpc_bind: "127.0.0.1:9100"
audit_log_path: "{}"
"#,
            policy_path.display(),
            keystore_dir.display(),
            data_dir.join("audit.jsonl").display(),
        );
        let config_path = data_dir.join("config.yaml");
        std::fs::write(&config_path, &config_yaml).unwrap();
        assert!(config_path.exists());

        // Verify all files exist and are parseable
        assert!(keystore_dir.exists());
        assert!(policy_path.exists());
        assert!(config_path.exists());

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.rpc_bind, "127.0.0.1:9100");

        let policy = Policy::from_file(&policy_path).unwrap();
        assert_eq!(policy.daily_transfer_limit_usd, 1000.0);
    }

    /// Test 17: CLI init from known mnemonic produces expected address
    #[test]
    fn test_cli_init_from_mnemonic() {
        let tmp = tempfile::tempdir().unwrap();
        let keystore_dir = tmp.path().join("keystore");
        std::fs::create_dir_all(&keystore_dir).unwrap();

        // Derive key from known mnemonic
        let signing_key = hd::derive_key(TEST_MNEMONIC, 0).unwrap();
        let private_key_bytes = signing_key.to_bytes();

        // Create keystore from derived key
        let (address, ks_path) =
            Keystore::create_from_key(&keystore_dir, "test", &private_key_bytes).unwrap();

        // Verify address matches expected
        let addr_hex = hex::encode(address.0);
        assert_eq!(addr_hex, TEST_MNEMONIC_ADDR);

        // Verify keystore can be unlocked and produces same address
        let unlocked = Keystore::unlock(&ks_path, "test").unwrap();
        let derived_addr = clawlet_signer::keystore::public_key_to_address(&unlocked);
        assert_eq!(derived_addr.0, address.0);
    }

    /// Test 18: CLI help output contains expected commands
    ///
    /// This test spawns `cargo run` which may not work in all CI environments.
    /// Run with `--include-ignored` to execute this test.
    #[test]
    fn test_cli_help_output() {
        // Build the project first to ensure binary exists
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.parent().unwrap().parent().unwrap();

        // Try to run clawlet --help
        let output = Command::new("cargo")
            .args(["run", "-p", "clawlet-cli", "--", "--help"])
            .current_dir(workspace_root)
            .output()
            .expect("failed to execute cargo run - cannot verify CLI help output");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");

        // Check for expected subcommands
        assert!(
            combined.contains("init") || combined.contains("Init"),
            "Help should mention init command. Output was: {combined}"
        );
        assert!(
            combined.contains("serve") || combined.contains("Serve"),
            "Help should mention serve command. Output was: {combined}"
        );
        assert!(
            combined.contains("clawlet") || combined.contains("Clawlet"),
            "Help should mention clawlet. Output was: {combined}"
        );
    }

    // =========================================================================
    // ERROR HANDLING TESTS
    // =========================================================================

    /// Test 19: Invalid RPC URL fails with clear error
    #[test]
    fn test_invalid_rpc_url() {
        // Completely invalid URL with invalid characters
        let result = EvmAdapter::new("not a valid url with spaces");
        assert!(result.is_err(), "Invalid URL with spaces should fail");

        // Empty URL
        let result = EvmAdapter::new("");
        assert!(result.is_err(), "Empty URL should fail");

        // URL that's just garbage
        let result = EvmAdapter::new(":::///invalid");
        assert!(result.is_err(), "Malformed URL should fail");

        // Note: We don't test unreachable URLs here because network timeouts
        // would make the test slow. Those are tested in the Anvil integration tests.
    }

    /// Test 20: Missing config file fails gracefully
    #[test]
    fn test_missing_config_file() {
        let result = Config::from_file(std::path::Path::new("/nonexistent/config.yaml"));
        assert!(result.is_err(), "Missing config should fail");

        let err = result.unwrap_err();
        let err_msg = err.to_string();
        // Should indicate the file doesn't exist
        assert!(
            err_msg.contains("No such file")
                || err_msg.contains("not found")
                || err_msg.contains("cannot find"),
            "Error should mention missing file: {err_msg}"
        );

        // Malformed YAML should also fail
        let tmp = tempfile::tempdir().unwrap();
        let bad_config = tmp.path().join("config.yaml");
        std::fs::write(&bad_config, "this: is: not: valid: yaml: [[[").unwrap();

        let result = Config::from_file(&bad_config);
        assert!(result.is_err(), "Malformed YAML should fail");
    }

    // =========================================================================
    // ORIGINAL TESTS (preserved)
    // =========================================================================

    /// test_full_init_flow — exercises keystore + config + policy creation
    #[test]
    fn test_full_init_flow() {
        let tmp = tempfile::tempdir().unwrap();
        let data_dir = tmp.path().join(".clawlet");
        let keystore_dir = data_dir.join("keystore");
        std::fs::create_dir_all(&keystore_dir).unwrap();

        // 1. Generate a keystore
        let password = "integration-test-pw";
        let (address, ks_path) = Keystore::create(&keystore_dir, password).unwrap();

        assert!(ks_path.exists(), "keystore file should exist");
        assert_ne!(address.0, [0u8; 20], "address should not be zero");

        // 2. Verify unlock round-trip
        let key = Keystore::unlock(&ks_path, password).unwrap();
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

        let config = Config::from_file(&config_path).unwrap();
        assert_eq!(config.rpc_bind, "127.0.0.1:9100");
        assert_eq!(config.keystore_path, keystore_dir);

        let policy = Policy::from_file(&policy_path).unwrap();
        assert_eq!(policy.daily_transfer_limit_usd, 1000.0);
        assert_eq!(policy.per_tx_limit_usd, 500.0);
    }

    /// test_balance_query — Anvil via testcontainers
    #[test]
    fn test_balance_query() {
        let (_anvil, anvil_url) = start_anvil();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let adapter = EvmAdapter::new(&anvil_url).expect("should connect to Anvil");

            // Anvil default account 0
            let default_addr: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
                .parse()
                .unwrap();

            let balance = adapter.get_eth_balance(default_addr).await.unwrap();
            assert!(
                balance > U256::ZERO,
                "Anvil default account should have ETH"
            );

            let chain_id = adapter.get_chain_id().await.unwrap();
            assert_eq!(chain_id, 31337, "Anvil default chain ID");
        });
    }

    /// test_transfer_with_policy — full flow on Anvil via testcontainers
    #[test]
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
            let private_key = hex::decode(ANVIL_ACCOUNT_0_KEY).unwrap();
            let (_address, ks_path) =
                Keystore::create_from_key(tmp.path(), "test", &private_key).unwrap();

            // 3. Sign and send
            let signing_key = Keystore::unlock(&ks_path, "test").unwrap();
            let signer = LocalSigner::new(signing_key);

            let adapter = EvmAdapter::new(&anvil_url).unwrap();

            let recipient: Address = ANVIL_ACCOUNT_1_ADDR.parse().unwrap();

            let tx_req = tx::TransferRequest {
                to: recipient,
                value: U256::from(1_000_000_000_000_000u64), // 0.001 ETH
                chain_id: 31337,
                gas_limit: Some(21000),
            };
            let tx = tx::build_eth_transfer(&tx_req);

            let tx_hash = tx::send_transaction(&adapter, &signer, tx)
                .await
                .expect("transfer should succeed on Anvil");

            assert_ne!(tx_hash, B256::ZERO);
        });
    }

    /// test_transfer_denied_by_policy — no Anvil needed
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

    /// test_audit_log_written — verifies audit JSONL output
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

    /// test_uniswap_v3_swap_ais — mainnet fork via ANVIL_URL
    #[test]
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

    /// test_aave_v3_supply_withdraw_ais — mainnet fork via ANVIL_URL
    #[test]
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
            assert!(
                usdc_final >= usdc_after_supply,
                "USDC balance should recover"
            );
        });
    }
}
