//! `clawlet serve` — start the RPC server.
//!
//! Loads config, unlocks keystore, starts the iceoryx2 IPC server,
//! and handles graceful shutdown on Ctrl+C.

use std::path::PathBuf;

use clawlet_core::config::Config;
use clawlet_rpc::server::RpcServer;
use clawlet_signer::keystore::Keystore;
use clawlet_signer::signer::LocalSigner;

/// Resolve the config path (default: ~/.clawlet/config.yaml).
fn resolve_config_path(config: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = config {
        return Ok(path);
    }

    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".clawlet").join("config.yaml"))
}

/// Run the `serve` subcommand.
pub async fn run(config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = resolve_config_path(config_path)?;

    tracing::info!("loading config from {}", config_path.display());
    let config = Config::from_file(&config_path)?;

    // Prompt for keystore password (used for future signing operations)
    eprint!("Enter keystore password: ");
    let password = rpassword::read_password()?;

    // Verify that keystore directory exists and has at least one key
    let signer = if config.keystore_path.exists() {
        let keys = Keystore::list(&config.keystore_path)?;
        if keys.is_empty() {
            return Err("no keystore files found — run `clawlet init` first".into());
        }
        tracing::info!("found {} keystore file(s)", keys.len());
        let (_addr, key_path) = &keys[0];
        let signing_key = Keystore::unlock(key_path, &password)?;
        Some(LocalSigner::new(signing_key))
    } else {
        None
    };
    let signer = signer.ok_or_else(|| {
        format!(
            "keystore directory does not exist: {} — run `clawlet init` first",
            config.keystore_path.display()
        )
    })?;

    println!("Clawlet RPC server running on {}", config.rpc_bind);

    // Start the RPC server (blocks until shutdown)
    RpcServer::start(&config, signer).await?;

    Ok(())
}
