# Changelog

## v0.1.24

### Features
- `clawlet connect` command with native UI dialog
- Detect owliabot runtime, improve install/uninstall scripts
- Token expiration optional (never expire by default)
- Detect non-interactive terminal + `CLAWLET_PASSWORD` env var

### Fixes
- Remove auth token step from start command
- Don't pass `--base-url` to owliabot wallet connect
- Read from stdin before falling back to default
- Remove expires references from auth/connect commands
- Rewrite localhost to `host.docker.internal` for Docker connect
- Fail connect command when owliabot returns non-zero
- Require save mnemonic
- Remove auto-start after install

### Refactor
- Remove expires parameter from start/auth grant
