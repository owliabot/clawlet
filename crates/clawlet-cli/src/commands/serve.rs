//! `clawlet serve` — start the RPC server.
//!
//! Loads config, unlocks keystore, starts the Unix socket server for JSON-RPC,
//! and handles graceful shutdown on Ctrl+C.

use std::path::PathBuf;

use clawlet_core::config::Config;
use clawlet_ipc::server::RpcServer;
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
pub async fn run(
    config_path: Option<PathBuf>,
    socket_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = resolve_config_path(config_path)?;

    tracing::info!("loading config from {}", config_path.display());
    let config = Config::from_file(&config_path)?;

    // Prompt for keystore password (used for future signing operations)
    eprint!("Enter keystore password: ");
    let password = rpassword::read_password()?;

    // Verify that keystore directory exists and has at least one key
    let signing_key = if config.keystore_path.exists() {
        let keys = Keystore::list(&config.keystore_path)?;
        if keys.is_empty() {
            return Err("no keystore files found — run `clawlet init` first".into());
        }
        tracing::info!("found {} keystore file(s)", keys.len());
        let (_addr, key_path) = &keys[0];
        Some(Keystore::unlock(key_path, &password)?)
    } else {
        None
    };
    let signing_key = signing_key.ok_or_else(|| {
        format!(
            "keystore directory does not exist: {} — run `clawlet init` first",
            config.keystore_path.display()
        )
    })?;

    let socket_display = socket_path
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| {
            clawlet_ipc::server::default_socket_path()
                .display()
                .to_string()
        });

    println!("Clawlet RPC server listening on {}", socket_display);

    // Start the Unix socket server
    RpcServer::start_with_config(&config, LocalSigner::new(signing_key), socket_path)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e })?;

    Ok(())
}
