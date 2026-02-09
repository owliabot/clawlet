# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.13] - 2026-02-09

### Fixed
- Set keystore files to `0600` permissions on init

## [0.1.11] - 2026-02-09

### Removed
- Remove Windows support (drop `install.ps1`, Windows release targets)
- Remove macOS x86_64 release target

### Fixed
- Fix release workflow configuration

## [0.1.10] - 2026-02-09

### Changed
- Refactor(core): remove custom `Address`/`TxHash` types, use alloy primitives directly (#31)
- Refactor(rpc): use strongly-typed serde deserialization for RPC params (#33)

### Added
- CLI: verify keystore file permissions (0600) before starting serve (#34)

## [0.1.5] - 2026-02-06

### Changed
- **Breaking**: IPC protocol changed from Unix domain sockets to HTTP JSON-RPC (#X)
  - Server now listens on `127.0.0.1:9100` by default (was Unix socket)
  - CLI `--socket` flag replaced with `--addr` flag
  - Authorization moved from request body (`meta.authorization`) to HTTP `Authorization` header
  - Removed `interprocess` crate dependency, added `axum`, `hyper`, `reqwest`

### Migration
- Old: `echo '...' | nc -U /run/clawlet/clawlet.sock`
- New: `curl -X POST http://127.0.0.1:9100/rpc -H "Authorization: Bearer clwt_xxx" -d '...'`

## [0.1.4] - 2026-02-06

### Added
- IPC: `address` query endpoint to get wallet address without requiring signed requests (#14)

### Fixed
- IPC: socket permissions changed from 660 to 600 for stricter security

## [0.1.3] - 2026-02-06

### Fixed
- CLI: resolve nested runtime panic in `auth grant` command (#13)

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
