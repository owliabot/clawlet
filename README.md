# 🐾 Clawlet

> Agent-native wallet engine for OpenClaw — 给本地 agent 用的链上操作引擎

Clawlet is a Rust-based wallet engine designed for AI agents operating within the [OpenClaw](https://github.com/openclaw) ecosystem. It provides policy-enforced, auditable on-chain operations with a local-first architecture.

## Features (Planned)

- **Policy Engine** — Configurable rules (daily limits, allowed tokens, recipient whitelists)
- **Audit Logging** — Append-only JSONL log of every operation
- **Keystore Management** — Encrypted key storage with BIP-44 HD derivation
- **EVM Support** — Balance queries, transfers, and DeFi operations via alloy
- **RPC Server** — Local HTTP API for agent integration
- **AIS Standard** — Agent Interaction Specification for protocol-level skill definitions

## Project Structure

```
clawlet/
├── crates/
│   ├── clawlet-core/       # Core types, policy engine, audit logging
│   ├── clawlet-signer/     # Key management and signing
│   ├── clawlet-evm/        # EVM chain adapter
│   ├── clawlet-ipc/        # HTTP RPC API server
│   └── clawlet-cli/        # CLI entry point (clawlet binary)
├── config/
│   └── policy.example.yaml # Example policy configuration
└── tests/
    └── integration/        # Integration tests
```

## Installation

### Quick Install (Linux/macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/owliabot/clawlet/main/scripts/install.sh | bash
```

### Windows (PowerShell)

```powershell
# Clone and run installer
git clone https://github.com/owliabot/clawlet.git
cd clawlet
.\scripts\install.ps1
```

### From Source

```bash
# Requires Rust toolchain: https://rustup.rs
git clone https://github.com/owliabot/clawlet.git
cd clawlet
cargo build --release
sudo cp target/release/clawlet /usr/local/bin/
```

### Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux    | x86_64       | ✅ Supported |
| Linux    | aarch64      | ✅ Supported |
| macOS    | x86_64       | ✅ Supported |
| macOS    | aarch64 (Apple Silicon) | ✅ Supported |
| Windows  | x86_64       | ✅ Supported |

### Uninstall

```bash
# Linux/macOS
curl -fsSL https://raw.githubusercontent.com/owliabot/clawlet/main/scripts/uninstall.sh | bash

# To also remove config files
./scripts/uninstall.sh --purge
```

## Quick Start

```bash
# Initialize (generates keystore + default policy)
clawlet init

# Start RPC server
clawlet serve    # Listens on 127.0.0.1:9100
```

## Architecture

Clawlet runs as a **local daemon** owned by a dedicated OS user. The agent communicates via authenticated HTTP on localhost. Private keys are managed by the human operator — the agent never has direct access to key material.

```
Agent ──HTTP──▶ clawlet-ipc ──▶ clawlet-core (policy check)
                     │                  │
                     ▼                  ▼
               clawlet-evm        audit log
                     │
                     ▼
               clawlet-signer ──▶ keystore (human-owned)
```

## Tech Stack

- **Language**: Rust
- **EVM Library**: alloy
- **Registry Chain**: Base (EIP-155:8453)
- **HTTP Server**: axum

## License

MIT — see [LICENSE](LICENSE) for details.
