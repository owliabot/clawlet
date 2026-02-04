# 🐾 clawlet

**Agent-native wallet engine for OpenClaw.**

Clawlet is a programmable wallet engine built for autonomous agents. It provides key management, transaction signing, and chain-abstracted wallet primitives — designed to be driven by AI agents rather than human UIs.

## Why?

Agents need wallets too. But existing wallet tooling assumes a human clicking buttons. Clawlet flips that: every operation is API-first, policy-gated, and designed for machine-speed decision-making.

## Features (planned)

- 🔐 **Key Management** — HD wallets, secure key storage, agent-scoped key derivation
- ✍️ **Transaction Signing** — Multi-chain signing with policy enforcement
- 🌐 **Chain Abstraction** — Unified interface across EVM, Solana, and more
- 🤖 **OpenClaw Integration** — Native hooks for agent workflows, approvals, and audit trails
- 🛡️ **Policy Engine** — Spending limits, allowlists, time-locks, multi-sig agent approval

## Quick Start

```bash
cargo build
cargo run
```

## Project Structure

```
clawlet/
├── Cargo.toml          # Workspace + main crate
├── src/
│   ├── lib.rs          # Core library
│   └── main.rs         # CLI binary
├── design.md           # Architecture notes
├── LICENSE             # MIT
└── README.md
```

## License

MIT — see [LICENSE](LICENSE).
