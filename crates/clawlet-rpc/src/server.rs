//! HTTP server powered by axum.
//!
//! Binds to the configured address and serves the Clawlet API.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use clawlet_core::audit::AuditLogger;
use clawlet_core::config::Config;
use clawlet_core::policy::PolicyEngine;
use clawlet_evm::EvmAdapter;
use tokio::net::TcpListener;

use crate::routes::build_router;

/// Shared application state available to all handlers.
#[derive(Clone)]
pub struct AppState {
    /// Policy engine for evaluating transfer requests.
    pub policy: Arc<PolicyEngine>,
    /// Audit logger (needs `&mut self`, so wrapped in `Mutex`).
    pub audit: Arc<Mutex<AuditLogger>>,
    /// EVM adapters keyed by chain ID.
    pub adapters: Arc<HashMap<u64, EvmAdapter>>,
    /// Authentication token required for API access.
    pub auth_token: String,
}

/// RPC server that holds shared state and serves the API.
pub struct RpcServer;

impl RpcServer {
    /// Start the RPC server using the provided configuration.
    ///
    /// This will:
    /// 1. Load the policy engine from the configured policy file
    /// 2. Create an audit logger at the configured path
    /// 3. Build EVM adapters for each configured chain
    /// 4. Bind to `config.rpc_bind` and serve HTTP requests
    pub async fn start(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
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

        // Resolve auth token: env var takes precedence
        let auth_token = std::env::var("CLAWLET_AUTH_TOKEN").unwrap_or_else(|_| String::new());

        let state = AppState {
            policy: Arc::new(policy),
            audit: Arc::new(Mutex::new(audit)),
            adapters: Arc::new(adapters),
            auth_token,
        };

        let app = build_router(state);

        let listener = TcpListener::bind(&config.rpc_bind).await?;
        tracing::info!("clawlet-rpc listening on {}", config.rpc_bind);

        axum::serve(listener, app).await?;

        Ok(())
    }
}
