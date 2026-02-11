//! `clawlet serve` — start the RPC server.
//!
//! Loads config, unlocks keystore, starts the HTTP JSON-RPC server,
//! and handles graceful shutdown on Ctrl+C.
//!
//! The command is split into [`prepare`] (synchronous: password prompt, keystore
//! unlock) and [`start`] (asynchronous: RPC server) so that daemon mode can
//! fork between the two phases — before any tokio worker threads exist.

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use clawlet_core::config::Config;
use clawlet_rpc::server::{RpcServer, DEFAULT_ADDR};
use clawlet_signer::hd;
use clawlet_signer::keystore::Keystore;
use clawlet_signer::signer::LocalSigner;

/// Everything needed to start the RPC server, produced by [`prepare`].
pub struct PreparedServer {
    pub config: Config,
    pub signer: LocalSigner,
    pub listen_addr: SocketAddr,
}

/// Resolve the config path (default: ~/.clawlet/config.yaml).
fn resolve_config_path(config: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = config {
        return Ok(path);
    }

    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".clawlet").join("config.yaml"))
}

/// Synchronous preparation: load config, prompt for password, unlock keystore.
///
/// This must run **before** daemonizing because it needs an interactive
/// terminal for the password prompt.
pub fn prepare(
    config_path: Option<PathBuf>,
    addr: Option<SocketAddr>,
) -> Result<PreparedServer, Box<dyn std::error::Error>> {
    let config_path = resolve_config_path(config_path)?;

    eprintln!("Loading config from {}", config_path.display());
    let config = Config::from_file(&config_path)?;

    // Prompt for keystore password (interactive)
    eprint!("Enter keystore password: ");
    let password = rpassword::read_password()?;

    // Verify keystore file permissions are 0600
    verify_keystore_permissions(&config.keystore_path)?;

    // Unlock keystore
    let signing_key = if config.keystore_path.exists() {
        let keys = Keystore::list(&config.keystore_path)?;
        if keys.is_empty() {
            return Err("no keystore files found — run `clawlet init` first".into());
        }
        eprintln!("Found {} keystore file(s)", keys.len());
        let key_path = &keys[0];
        let mnemonic = Keystore::unlock(key_path, &password)?;
        Some(hd::derive_key(&mnemonic, 0)?)
    } else {
        None
    };
    let signing_key = signing_key.ok_or_else(|| {
        format!(
            "keystore directory does not exist: {} — run `clawlet init` first",
            config.keystore_path.display()
        )
    })?;

    // Priority: CLI --addr > config.rpc_bind > DEFAULT_ADDR
    let listen_addr = addr.unwrap_or_else(|| {
        config
            .rpc_bind
            .parse()
            .unwrap_or_else(|_| DEFAULT_ADDR.parse().unwrap())
    });

    Ok(PreparedServer {
        config,
        signer: LocalSigner::new(signing_key),
        listen_addr,
    })
}

/// Start the RPC server with previously prepared state (async).
pub async fn start(prepared: PreparedServer) -> Result<(), Box<dyn std::error::Error>> {
    start_notify(prepared, None).await
}

/// Start the RPC server with previously prepared state and optional ready notification fd.
///
/// If `ready_fd` is provided, "ok\n" will be written to it after the RPC server
/// successfully binds, signaling daemon readiness to the parent process.
#[cfg(unix)]
pub async fn start_notify(
    prepared: PreparedServer,
    ready_fd: impl Into<Option<i32>>,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("starting RPC server on http://{}", prepared.listen_addr);

    // Start the HTTP JSON-RPC server
    RpcServer::start_with_config_notify(
        &prepared.config,
        prepared.signer,
        Some(prepared.listen_addr),
        ready_fd.into(),
    )
    .await?;

    Ok(())
}

#[cfg(not(unix))]
pub async fn start_notify(
    prepared: PreparedServer,
    _ready_fd: impl Into<Option<i32>>,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("starting RPC server on http://{}", prepared.listen_addr);

    RpcServer::start_with_config_notify(
        &prepared.config,
        prepared.signer,
        Some(prepared.listen_addr),
        None,
    )
    .await?;

    Ok(())
}

/// Run the `serve` subcommand (non-daemon mode).
pub async fn run(
    config_path: Option<PathBuf>,
    addr: Option<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let prepared = prepare(config_path, addr)?;

    println!(
        "Clawlet RPC server listening on http://{}",
        prepared.listen_addr
    );

    start(prepared).await
}

/// Verify that the keystore directory and all keystore files have permission 0600.
///
/// This prevents accidentally running with world-readable private keys.
fn verify_keystore_permissions(keystore_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !keystore_path.exists() {
        return Err(format!(
            "keystore directory does not exist: {} — run `clawlet init` first",
            keystore_path.display(),
        )
        .into());
    }

    // Check each keystore file (must be 0600)
    for entry in fs::read_dir(keystore_path)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(format!(
                "keystore file {} has insecure permissions {:04o} (expected 0600). \
                 Fix with: chmod 600 {}",
                path.display(),
                mode,
                path.display(),
            )
            .into());
        }
    }

    eprintln!("Keystore permissions verified: {}", keystore_path.display());
    Ok(())
}
