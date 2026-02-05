//! `clawlet serve` — start the RPC server.
//!
//! Loads config, unlocks keystore, starts the iceoryx2 IPC server by default,
//! or starts the Unix socket server for non-Rust clients instead,
//! and handles graceful shutdown on Ctrl+C.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use clawlet_core::audit::AuditLogger;
use clawlet_core::auth::SessionStore;
use clawlet_core::config::Config;
use clawlet_core::policy::PolicyEngine;
use clawlet_evm::EvmAdapter;
use clawlet_ipc::server::{AppState, RpcServer};
use clawlet_ipc::socket::{SocketServer, SocketServerConfig};
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

    println!("Clawlet RPC server running on {}", config.rpc_bind);

    // If socket path is provided, start the Unix socket server instead of iceoryx2.
    if let Some(socket_path) = socket_path {
        // Build AppState for the socket server.
        let state = Arc::new(build_app_state(&config, LocalSigner::new(signing_key))?);

        let socket_config = SocketServerConfig {
            socket_path: socket_path.clone(),
            permissions: 0o660,
        };

        let socket_server = SocketServer::new(socket_config, Arc::clone(&state));

        println!("Unix socket server listening on {}", socket_path.display());

        // For now, just start the socket server (iceoryx2 uses its own AppState internally).
        // In the future, we could refactor RpcServer to accept an Arc<AppState>.
        socket_server
            .start()
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e })?;
    } else {
        // Start only the iceoryx2 RPC server (blocks until shutdown)
        RpcServer::start(&config, LocalSigner::new(signing_key)).await?;
    }

    Ok(())
}

/// Build AppState from config and signer.
fn build_app_state(
    config: &Config,
    signer: LocalSigner,
) -> Result<AppState, Box<dyn std::error::Error>> {
    // Load policy
    let policy = PolicyEngine::from_file(&config.policy_path)?;

    // Create audit logger (ensure parent dir exists)
    if let Some(parent) = config.audit_log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let audit = AuditLogger::new(&config.audit_log_path)?;

    // Build EVM adapters for each configured chain
    let mut adapters = HashMap::new();
    for (chain_id, rpc_url) in &config.chain_rpc_urls {
        let adapter = EvmAdapter::new(rpc_url)?;
        adapters.insert(*chain_id, adapter);
    }

    // Initialize session store
    let session_store = SessionStore::new();

    let skills_dir = std::env::var("CLAWLET_SKILLS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("skills"));

    Ok(AppState {
        policy: Arc::new(policy),
        audit: Arc::new(Mutex::new(audit)),
        adapters: Arc::new(adapters),
        session_store: Arc::new(RwLock::new(session_store)),
        auth_config: config.auth.clone(),
        signer: Arc::new(signer),
        skills_dir,
    })
}
