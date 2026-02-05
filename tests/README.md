# Integration Tests

## Overview

Integration tests exercise Clawlet's full flow: keystore creation, policy enforcement, balance queries, transaction signing/broadcasting, and audit logging.

Tests that require external infrastructure (Anvil) are marked `#[ignore]` so they won't run in CI.

## Prerequisites

- **Rust toolchain** (stable)
- **Anvil** (from [Foundry](https://book.getfoundry.sh/getting-started/installation))

## Running Tests

### Unit tests only (CI default)

```bash
cargo test --workspace
```

### Integration tests with Anvil

1. Start Anvil in a separate terminal:

```bash
anvil
```

This starts a local Ethereum node at `http://127.0.0.1:8545` with 10 pre-funded accounts.

2. Run the ignored integration tests:

```bash
cargo test --test integration -- --ignored
```

3. Or run everything (unit + integration):

```bash
cargo test --workspace -- --include-ignored
```

## Test Descriptions

| Test | Needs Anvil | Description |
|------|:-----------:|-------------|
| `test_full_init_flow` | No | Creates keystore + config + policy files, verifies parsing |
| `test_balance_query` | Yes | Queries ETH balance on Anvil default account |
| `test_transfer_with_policy` | Yes | Full flow: policy check → sign → broadcast ETH transfer |
| `test_transfer_denied_by_policy` | No | Verifies policy engine denies over-limit transfers |
| `test_audit_log_written` | No | Writes audit events and verifies JSONL output |

## Anvil Default Accounts

Anvil starts with 10 pre-funded accounts (10,000 ETH each). The tests use:

- **Account 0** (sender): `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`
  - Private key: `0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80`
- **Account 1** (recipient): `0x70997970C51812dc3A010C7d01b50e0d17dc79C8`

## Troubleshooting

- **Connection refused**: Make sure Anvil is running on port 8545
- **Tests timing out**: Anvil may have been restarted — nonces reset on restart
- **Wrong chain ID**: Default Anvil chain ID is `31337`
