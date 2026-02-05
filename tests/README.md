# Integration Tests

## Overview

Comprehensive integration tests for Clawlet's wallet engine:

- **Keystore management** — creation, unlock, HD derivation
- **Policy enforcement** — daily/per-tx limits, token/chain allowlists, approval thresholds
- **Balance queries** — ETH and ERC-20 balances
- **Transaction signing** — sign and broadcast ETH transfers
- **Audit logging** — JSONL event logging
- **RPC API** — iceoryx2 IPC request-response
- **CLI operations** — init, serve, help

Tests requiring external infrastructure (Anvil) are marked `#[ignore]` so they won't run in CI.

## Test Categories

### Unit Tests (No External Dependencies)
- Keystore unlock/wrong password
- HD derivation (5 unique addresses)
- Policy YAML parsing
- Policy decision logic
- Audit log JSONL format
- RPC message types
- Config file parsing
- Error handling

### Integration Tests (Require Anvil)
Marked with `#[ignore]` — run manually with `--include-ignored`:

| Test | Description |
|------|-------------|
| `test_init_and_serve_roundtrip` | Full init → config → serve → health check flow |
| `test_eth_balance_query_on_anvil` | Query ETH balance (should be 10000 ETH) |
| `test_eth_transfer_on_anvil` | Transfer ETH between accounts |
| `test_erc20_transfer_on_anvil` | ERC-20 token operations |
| `test_transfer_blocked_by_policy` | Verify policy blocks disallowed transfers |
| `test_transfer_with_policy` | Full policy check → sign → broadcast flow |
| `test_uniswap_v3_swap_ais` | Uniswap swap (mainnet fork) |
| `test_aave_v3_supply_withdraw_ais` | Aave supply/withdraw (mainnet fork) |

## Prerequisites

- **Rust toolchain** (stable)
- **Anvil** (from [Foundry](https://book.getfoundry.sh/getting-started/installation)) — for Anvil tests
- **Docker** (optional) — testcontainers can auto-start Anvil

## Running Tests

### Unit tests only (CI default)

```bash
cargo test --workspace
```

### All tests (with Anvil via testcontainers)

Requires Docker running:

```bash
cargo test -p clawlet-integration-tests -- --include-ignored
```

### Manual Anvil setup (without Docker)

1. Start Anvil in a separate terminal:

```bash
anvil
```

This starts a local Ethereum node at `http://127.0.0.1:8545` with 10 pre-funded accounts.

2. Run the ignored integration tests:

```bash
cargo test -p clawlet-integration-tests -- --ignored
```

### Mainnet fork tests (for DeFi integrations)

Set environment variables and run:

```bash
export ANVIL_URL="http://127.0.0.1:8545"
export ANVIL_PRIVATE_KEY="ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

# Start Anvil with mainnet fork
anvil --fork-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY

# Run tests
cargo test -p clawlet-integration-tests -- --ignored
```

## Test Descriptions

### Full Flow Tests

| Test | Anvil | Description |
|------|:-----:|-------------|
| `test_init_and_serve_roundtrip` | Yes | Init keystore → config → connect → health check |
| `test_eth_balance_query_on_anvil` | Yes | Query ETH balance, verify 10000 ETH |
| `test_eth_transfer_on_anvil` | Yes | Transfer 1 ETH, verify balance changes |
| `test_erc20_transfer_on_anvil` | Yes | ERC-20 balance query |
| `test_transfer_blocked_by_policy` | Yes | Policy denies, verify no tx sent |

### Policy Tests

| Test | Anvil | Description |
|------|:-----:|-------------|
| `test_transfer_requires_approval` | No | Over threshold returns RequiresApproval |
| `test_transfer_denied_by_policy` | No | Exceeds limits returns Denied |
| `test_policy_from_example_config` | No | Parse config/policy.example.yaml |
| `test_policy_daily_limit_across_multiple_checks` | No | Accumulation over multiple transfers |
| `test_policy_with_custom_yaml` | No | Custom restrictive/permissive policies |

### RPC Tests

| Test | Anvil | Description |
|------|:-----:|-------------|
| `test_rpc_health_endpoint` | No | Health request/response types |
| `test_rpc_auth_required` | No | Missing token → Unauthorized |
| `test_rpc_auth_valid` | No | Valid token → Ok |

### CLI Tests

| Test | Anvil | Description |
|------|:-----:|-------------|
| `test_cli_init_creates_files` | No | Init creates keystore, config, policy |
| `test_cli_init_from_mnemonic` | No | Restore from known mnemonic |
| `test_cli_help_output` | No | Help text contains expected commands |

### Keystore Tests

| Test | Anvil | Description |
|------|:-----:|-------------|
| `test_keystore_unlock_wrong_password` | No | Wrong password fails gracefully |
| `test_hd_derivation_multiple_accounts` | No | Derive 5 unique addresses |
| `test_full_init_flow` | No | Create + unlock keystore round-trip |

### Error Handling Tests

| Test | Anvil | Description |
|------|:-----:|-------------|
| `test_invalid_rpc_url` | No | Bad URL fails with clear error |
| `test_missing_config_file` | No | Missing/malformed config fails |

### Audit Tests

| Test | Anvil | Description |
|------|:-----:|-------------|
| `test_audit_log_written` | No | 3 events written to JSONL |
| `test_audit_log_records_all_operations` | No | 5 events with timestamps |

## Anvil Default Accounts

Anvil starts with 10 pre-funded accounts (10,000 ETH each). The tests use:

- **Account 0** (sender): `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`
  - Private key: `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`
- **Account 1** (recipient): `0x70997970C51812dc3A010C7d01b50e0d17dc79C8`

## Test Mnemonic

For deterministic testing, some tests use the standard BIP-39 test mnemonic:

```
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
```

Expected address at `m/44'/60'/0'/0/0`: `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`

## Troubleshooting

- **Connection refused**: Make sure Anvil is running on port 8545
- **Docker not available**: Install Docker or run Anvil manually
- **Tests timing out**: Anvil may need restart — nonces reset on restart
- **Wrong chain ID**: Default Anvil chain ID is `31337`
- **Mainnet fork tests failing**: Check RPC URL and API key
- **Test still running**: Some tests have network timeouts; use `Ctrl+C` and retry
