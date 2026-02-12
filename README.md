# 🐾 Clawlet

> Agent-native wallet engine for OpenClaw — 给本地 agent 用的链上操作引擎

Clawlet is a Rust-based wallet engine designed for AI agents operating within the [OpenClaw](https://github.com/openclaw) ecosystem. It provides policy-enforced, auditable on-chain operations with a local-first architecture.

## Features

- **Policy Engine** — Configurable rules (daily limits, allowed tokens, recipient whitelists)
- **Audit Logging** — Append-only JSONL log of every operation
- **Keystore Management** — Encrypted key storage with BIP-44 HD derivation
- **EVM Support** — Balance queries, transfers, and DeFi operations via alloy
- **HTTP RPC Server** — JSON-RPC 2.0 over HTTP for agent integration
- **Session Auth** — Token-based access control with scoped permissions

## Project Structure

```
clawlet/
├── crates/
│   ├── clawlet-core/       # Core types, policy engine, audit logging, auth
│   ├── clawlet-signer/     # Key management and signing
│   ├── clawlet-evm/        # EVM chain adapter
│   ├── clawlet-rpc/        # HTTP JSON-RPC 2.0 server
│   └── clawlet-cli/        # CLI entry point (clawlet binary)
├── config/
│   └── policy.example.yaml # Example policy configuration
├── docs/
│   ├── usage.md            # Usage guide
│   └── deployment.md       # Deployment guide
└── tests/
    └── integration/        # Integration tests
```

## Installation

### Isolated Mode (Recommended)

Isolated mode creates a dedicated `clawlet` system user for key isolation — recommended for all deployments:

```bash
# Linux - installs binary, creates user, sets up systemd service
curl -fsSL https://raw.githubusercontent.com/owliabot/clawlet/main/scripts/install.sh -o /tmp/clawlet-install.sh && sudo bash /tmp/clawlet-install.sh --isolated

# macOS - installs binary, creates user, sets up launchd service
curl -fsSL https://raw.githubusercontent.com/owliabot/clawlet/main/scripts/install.sh -o /tmp/clawlet-install.sh && sudo bash /tmp/clawlet-install.sh --isolated
```

**Isolated mode provides:**
- Dedicated `clawlet` system user (cannot login)
- Keystore isolated from agent processes
- Data directory with 700 permissions
- Auto-configured systemd (Linux) or launchd (macOS) service
- Security hardening (NoNewPrivileges, ProtectSystem, etc.)

**Post-install steps:**
```bash
# Init + grant token + start daemon (all-in-one)
sudo -H -u clawlet clawlet start --agent owliabot --daemon
```

See [docs/deployment.md](docs/deployment.md) for full production setup guide.

### Quick Install (Dev Mode)

```bash
# Download and install (pre-built binary)
curl -fsSL https://raw.githubusercontent.com/owliabot/clawlet/main/scripts/install.sh -o /tmp/clawlet-install.sh && bash /tmp/clawlet-install.sh

# Or with options
curl -fsSL https://raw.githubusercontent.com/owliabot/clawlet/main/scripts/install.sh -o /tmp/clawlet-install.sh
bash /tmp/clawlet-install.sh --prefix ~/.local    # Custom install location
bash /tmp/clawlet-install.sh --from-source        # Build from source
bash /tmp/clawlet-install.sh --version v0.1.0     # Specific version
```

### From Source

```bash
# Requires Rust toolchain: https://rustup.rs
git clone https://github.com/owliabot/clawlet.git
cd clawlet
cargo build --release
sudo cp target/release/clawlet /usr/local/bin/
```

### Uninstall

```bash
# Dev mode
curl -fsSL https://raw.githubusercontent.com/owliabot/clawlet/main/scripts/uninstall.sh -o /tmp/clawlet-uninstall.sh && bash /tmp/clawlet-uninstall.sh

# Isolated mode (removes service, optionally user and data)
curl -fsSL https://raw.githubusercontent.com/owliabot/clawlet/main/scripts/uninstall.sh -o /tmp/clawlet-uninstall.sh && sudo bash /tmp/clawlet-uninstall.sh --isolated

# Full cleanup (removes user, data, and keystore)
curl -fsSL https://raw.githubusercontent.com/owliabot/clawlet/main/scripts/uninstall.sh -o /tmp/clawlet-uninstall.sh && sudo bash /tmp/clawlet-uninstall.sh --isolated --purge
```

### Platform Support

| Platform | Architecture | Status |
|----------|--------------|--------|
| Linux    | x86_64       | ✅ Supported |
| Linux    | aarch64      | ✅ Supported |
| macOS    | aarch64 (Apple Silicon) | ✅ Supported |

## Quick Start

```bash
# 1. Start clawlet (init + grant token + start server, all-in-one)
clawlet start --agent my-agent
# Listening on http://127.0.0.1:9100

# 2. Test
curl -X POST http://127.0.0.1:9100/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"health","params":{},"id":1}'
```

## Architecture

Clawlet runs as a **local daemon** owned by a dedicated OS user. The agent communicates via JSON-RPC 2.0 over HTTP. Private keys are managed by the human operator — the agent never has direct access to key material.

```
Agent ────HTTP────▶ clawlet-rpc ──▶ clawlet-core (policy + auth)
       JSON-RPC 2.0       │                  │
                          ▼                  ▼
                    clawlet-evm        audit log
                          │
                          ▼
                    clawlet-signer ──▶ keystore (human-owned)
```

### Security Model

| Component | Access |
|-----------|--------|
| `clawlet` user | Owns keystore, runs daemon |
| Agent user | HTTP access only, token-authenticated |
| Keystore | 600 permissions, encrypted with password |

## API Methods

| Method | Scope | Description |
|--------|-------|-------------|
| `health` | — | Health check |
| `address` | — | Get wallet address |
| `balance` | `read` | Query ETH/ERC-20 balances |
| `transfer` | `trade` | Execute transfers (policy-checked) |
| `auth.grant` | — | Grant new session token |
| `auth.list` | — | List all sessions (including expired in grace period) |
| `auth.revoke` | — | Revoke all sessions for an agent |
| `auth.revoke_session` | — | Revoke a single session by key |

See [docs/usage.md](docs/usage.md) for full API documentation.

## Tech Stack

- **Language**: Rust
- **EVM Library**: alloy
- **HTTP Server**: axum
- **Protocol**: JSON-RPC 2.0

## Documentation

- [Usage Guide](docs/usage.md) — Installation, configuration, API reference
- [Deployment Guide](docs/deployment.md) — Production setup, systemd, security hardening

## License

MIT — see [LICENSE](LICENSE) for details.
