# Clawlet — Architecture Design

## Overview

Clawlet is an **agent-native wallet engine**: a wallet runtime where the primary consumer is an autonomous AI agent, not a human with a GUI. Every design decision optimizes for programmatic access, policy enforcement, and auditability.

## Core Modules

### 1. Key Management (`keyring`)

- **HD Wallet Derivation** — BIP-32/44 hierarchical deterministic keys
- **Agent-Scoped Keys** — Each agent gets a derived keypair from a master seed, isolating blast radius
- **Storage Backends** — Pluggable: in-memory (dev), encrypted file, HSM/KMS (production)
- **Key Rotation** — Automated rotation with grace periods for pending transactions

```
Master Seed
  └─ Agent A (m/44'/60'/0')
  │    ├─ Spending Key (m/44'/60'/0'/0/0)
  │    └─ Signing Key  (m/44'/60'/0'/0/1)
  └─ Agent B (m/44'/60'/1')
       └─ ...
```

### 2. Transaction Signing (`signer`)

- **Stateless Signing** — Receives transaction payloads, returns signatures. No state mutation.
- **Multi-Chain Support** — EVM (secp256k1/keccak), Solana (ed25519), Bitcoin (secp256k1/sha256d)
- **Pre-Sign Hooks** — Policy checks run before any signature is produced
- **Batch Signing** — Sign multiple transactions atomically

### 3. Chain Abstraction Layer (`chain`)

Unified interface over heterogeneous blockchains:

```rust
trait ChainProvider {
    fn chain_id(&self) -> ChainId;
    fn balance(&self, address: &Address) -> Result<Amount>;
    fn submit_tx(&self, signed: &SignedTransaction) -> Result<TxHash>;
    fn tx_status(&self, hash: &TxHash) -> Result<TxStatus>;
    fn estimate_fee(&self, tx: &UnsignedTransaction) -> Result<Fee>;
}
```

**Supported chains (roadmap):**
- EVM (Ethereum, Polygon, Arbitrum, Base, etc.)
- Solana
- Bitcoin (watch-only initially)
- Cosmos/IBC

### 4. Policy Engine (`policy`)

The critical differentiator. Agents shouldn't have unlimited spending power.

- **Spending Limits** — Per-agent, per-chain, per-token daily/weekly/lifetime caps
- **Allowlists/Blocklists** — Restrict destination addresses
- **Time Locks** — Require delay for large transactions (human can cancel)
- **Multi-Agent Approval** — N-of-M agent consensus for high-value ops
- **Gas Guards** — Reject transactions with abnormal gas pricing

```rust
struct Policy {
    max_per_tx: Amount,
    max_per_day: Amount,
    allowed_recipients: Vec<Address>,
    blocked_contracts: Vec<Address>,
    require_approval_above: Amount,
    cooldown_seconds: u64,
}
```

### 5. OpenClaw Integration (`bridge`)

Native integration points with the OpenClaw agent runtime:

- **Agent Identity** — Map OpenClaw agent sessions to wallet keypairs
- **Approval Flow** — High-value transactions route through OpenClaw's human-in-the-loop
- **Audit Trail** — Every signing event logged to OpenClaw's event system
- **Tool Interface** — Expose wallet ops as OpenClaw tools (balance, send, sign, etc.)
- **Notification Hooks** — Alert channels on suspicious activity

## Data Flow

```
Agent Request
    │
    ▼
┌──────────┐     ┌──────────┐     ┌──────────┐
│  Bridge   │────▶│  Policy  │────▶│  Signer  │
│ (OpenClaw)│     │  Engine  │     │          │
└──────────┘     └──────────┘     └──────────┘
                      │                 │
                 DENY / APPROVE    Signed TX
                                       │
                                       ▼
                                 ┌──────────┐
                                 │  Chain    │
                                 │ Provider  │
                                 └──────────┘
                                       │
                                       ▼
                                  Blockchain
```

## Security Considerations

- **No plaintext keys in memory longer than necessary** — zeroize on drop
- **All signing operations are logged** — append-only audit log
- **Policy evaluation is mandatory** — no bypass path in the API
- **Secrets backend is pluggable** — dev uses files, prod uses KMS
- **Rate limiting at the engine level** — prevent agent runaway

## Crate Structure (future)

```
clawlet/
├── crates/
│   ├── clawlet-keyring/    # Key management
│   ├── clawlet-signer/     # Transaction signing
│   ├── clawlet-chain/      # Chain abstraction
│   ├── clawlet-policy/     # Policy engine
│   └── clawlet-bridge/     # OpenClaw integration
├── src/
│   ├── lib.rs              # Re-exports from crates
│   └── main.rs             # CLI entrypoint
└── Cargo.toml              # Workspace root
```

## Open Questions

- [ ] Should policy rules be WASM-pluggable for user-defined logic?
- [ ] How to handle nonce management across concurrent agent sessions?
- [ ] Encrypted backup/restore strategy for agent keys
- [ ] Support for MPC/TSS signing schemes?
- [ ] Integration with account abstraction (ERC-4337)?
