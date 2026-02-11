# Clawlet Deployment Guide

## Overview

Clawlet uses **OS user isolation** to protect private keys: the keystore runs under a dedicated `clawlet` system user, while agent processes communicate only through the RPC interface bound to `127.0.0.1`.

```
┌──────────────────────────────────────────────────┐
│  Host Machine                                     │
│                                                   │
│  ┌─────────────┐       HTTP (127.0.0.1:9100)     │
│  │  Agent User  │ ────────────────────────────►   │
│  │  (cannot     │       Bearer token auth         │
│  │   read keys) │                                 │
│  └─────────────┘       ┌──────────────────────┐  │
│                        │  clawlet user         │  │
│                        │  ┌──────────────────┐ │  │
│                        │  │ clawlet serve    │ │  │
│                        │  │ (RPC server)     │ │  │
│                        │  └──────┬───────────┘ │  │
│                        │         │             │  │
│                        │  ┌──────▼───────────┐ │  │
│                        │  │ ~/.clawlet/      │ │  │
│                        │  │ ├── keystore/    │ │  │
│                        │  │ ├── config.yaml  │ │  │
│                        │  │ ├── policy.yaml  │ │  │
│                        │  │ └── audit.jsonl  │ │  │
│                        │  └──────────────────┘ │  │
│                        └──────────────────────┘  │
└──────────────────────────────────────────────────┘
```

## 1. OS User Isolation Model

| User | Role | Access |
|------|------|--------|
| `clawlet` | System user — owns keystore and runs the RPC server | Full access to `~/.clawlet/` including encrypted keys |
| Agent user (e.g. `ocbot`) | AI agent process | HTTP access to `127.0.0.1:9100` only — cannot read keystore files |

**Why?** Even if an agent is compromised, it cannot read the encrypted keystore directly. All operations go through the RPC layer, which enforces policy checks and audit logging.

## 2. Directory Layout

```
~/.clawlet/                     # CLAWLET_HOME (default: /home/clawlet/.clawlet)
├── config.yaml                 # Main configuration
├── policy.yaml                 # Transfer policy rules
├── keystore/                   # Encrypted V3 keystore files (chmod 700)
│   └── UTC--2026-...--<addr>   # One file per wallet
└── audit.jsonl                 # Append-only audit log
```

### File Permissions

```
~/.clawlet/           drwx------  clawlet:clawlet  (700)
├── config.yaml       -rw-------  clawlet:clawlet  (600)
├── policy.yaml       -rw-------  clawlet:clawlet  (600)
├── keystore/         drwx------  clawlet:clawlet  (700)
│   └── UTC--*        -rw-------  clawlet:clawlet  (600)
└── audit.jsonl       -rw-------  clawlet:clawlet  (600)
```

## 3. Setup Steps

### 3.1 Create the system user

```bash
sudo useradd --system --create-home --shell /usr/sbin/nologin clawlet
```

### 3.2 Install the binary

```bash
# Build from source
cargo build --release -p clawlet-cli

# Install to /usr/local/bin
sudo cp target/release/clawlet /usr/local/bin/clawlet
sudo chmod 755 /usr/local/bin/clawlet
```

### 3.3 Initialize

**Recommended:** Use `clawlet start` to init, grant token, and start the server in one step:

```bash
sudo -H -u clawlet clawlet start --agent owliabot --daemon
```

**Or manually:**

```bash
# Run as the clawlet user
sudo -u clawlet clawlet init
```

This creates:
- `~clawlet/.clawlet/keystore/` with a new encrypted wallet
- `~clawlet/.clawlet/config.yaml` with defaults
- `~clawlet/.clawlet/policy.yaml` with default limits

### 3.4 Configure

Edit the config to add chain RPC URLs:

```bash
sudo -u clawlet nano ~clawlet/.clawlet/config.yaml
```

Example additions:

```yaml
chain_rpc_urls:
  1: "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
  8453: "https://mainnet.base.org"
```

Edit the policy to set appropriate limits:

```bash
sudo -u clawlet nano ~clawlet/.clawlet/policy.yaml
```

### 3.5 Lock down permissions

```bash
sudo chmod 700 ~clawlet/.clawlet
sudo chmod 700 ~clawlet/.clawlet/keystore
sudo chmod 600 ~clawlet/.clawlet/keystore/*
sudo chmod 600 ~clawlet/.clawlet/config.yaml
sudo chmod 600 ~clawlet/.clawlet/policy.yaml
```

## 4. Systemd Service

Create `/etc/systemd/system/clawlet.service`:

```ini
[Unit]
Description=Clawlet Wallet Engine
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=clawlet
Group=clawlet

# Environment
Environment=RUST_LOG=info
Environment=CLAWLET_HOME=/home/clawlet/.clawlet

# Execution
ExecStart=/usr/local/bin/clawlet serve
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/home/clawlet/.clawlet
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
```

### Enable and start

```bash
sudo systemctl daemon-reload
sudo systemctl enable clawlet
sudo systemctl start clawlet
sudo systemctl status clawlet
```

### View logs

```bash
sudo journalctl -u clawlet -f
```

## 5. Security Checklist

### File System

- [ ] Keystore directory is `chmod 700`, owned by `clawlet`
- [ ] All keystore files are `chmod 600`, owned by `clawlet`
- [ ] Config and policy files are `chmod 600`, owned by `clawlet`
- [ ] Audit log is `chmod 600`, owned by `clawlet`
- [ ] Agent user **cannot** read any files under `~clawlet/.clawlet/`

### Network

- [ ] RPC server binds to `127.0.0.1` only (not `0.0.0.0`)
- [ ] Firewall blocks external access to port 9100
- [ ] If reverse proxy is used, it terminates TLS and authenticates

### Authentication

- [ ] Bearer token is set and sufficiently random (≥ 32 bytes)
- [ ] Token is rotated periodically (at least quarterly)
- [ ] Token is stored in a file readable only by the agent user (not in env vars visible to `ps`)

### Operations

- [ ] Policy limits are set conservatively (start low, increase as needed)
- [ ] `require_approval_above_usd` is configured for high-value transfers
- [ ] Audit log is monitored / rotated (e.g., `logrotate`)
- [ ] Keystore password is strong and stored securely (not in config files)
- [ ] Systemd security hardening options are enabled (see unit file above)

### Backup

- [ ] Mnemonic phrase is stored offline in a secure location
- [ ] Keystore files are backed up to encrypted storage
- [ ] Recovery procedure is documented and tested

## 6. Quick Start

```bash
# 1. Create system user
sudo useradd --system --create-home --shell /usr/sbin/nologin clawlet

# 2. Install binary
cargo build --release -p clawlet-cli
sudo cp target/release/clawlet /usr/local/bin/clawlet

# 3. Initialize + start (all-in-one)
sudo -H -u clawlet clawlet start --agent owliabot --daemon

# 4. Configure RPC URLs
sudo -u clawlet bash -c 'cat >> ~/.clawlet/config.yaml << EOF
chain_rpc_urls:
  8453: "https://mainnet.base.org"
EOF'

# 5. Lock permissions
sudo chmod -R go-rwx ~clawlet/.clawlet

# 6. Install and start systemd service
sudo cp docs/clawlet.service /etc/systemd/system/clawlet.service
sudo systemctl daemon-reload
sudo systemctl enable --now clawlet

# 7. Verify
curl -s http://127.0.0.1:9100/health
```

The agent can now make requests to `http://127.0.0.1:9100` with the configured bearer token.
