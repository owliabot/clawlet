# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-02-06

### Added
- Use keystore password for auth — eliminates separate auth token, single password for both keystore unlock and IPC authentication (#12)

### Fixed
- Install script: handle unset tmp_dir in trap
- Install script: redirect info messages to stderr in captured functions

## [0.1.1] - 2026-02-06

### Fixed
- CI: use macos-14 runner for Apple Silicon builds (#10)

### Documentation
- Add install script to README and usage guide (#11)
- Update README - IPC architecture, remove HTTP references
- Fix usage guide - IPC mode only, no HTTP
- Add comprehensive usage guide (中文)
- Add changelog generation to release script

## [0.1.0] - 2026-02-06

### Added

#### clawlet-core
- Policy engine with YAML configuration support
- Daily and per-transaction spending limits
- Token and chain allowlists
- Audit logger with append-only JSONL format
- Configuration parser

#### clawlet-signer
- Ethereum V3 keystore support (scrypt/AES-128-CTR)
- BIP-44 HD key derivation
- Signer trait with EIP-191 personal message signing

#### clawlet-evm
- ETH and ERC-20 balance queries
- Transfer transaction building, signing, and broadcasting
- EIP-155 replay protection
- alloy-based ABI encoding

#### clawlet-ipc
- Unix domain socket IPC server
- JSON-RPC 2.0 protocol support
- Session-based authentication
- Password hashing with argon2id

#### clawlet-cli
- `clawlet init` command for keystore and config generation
- `clawlet serve` command for IPC server
- `clawlet auth grant/list/revoke` commands for session management

#### Infrastructure
- Integration test suite with testcontainers-rs
- Multi-platform install scripts (Linux/macOS)
- Deployment documentation with systemd service configuration
- OS user isolation guide

[0.1.1]: https://github.com/ArcadeLabsInc/clawlet/releases/tag/v0.1.1
[0.1.0]: https://github.com/ArcadeLabsInc/clawlet/releases/tag/v0.1.0
