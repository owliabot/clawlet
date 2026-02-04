//! IPC server powered by iceoryx2 request-response.
//!
//! Creates a named service and processes RPC requests in a blocking loop
//! on a dedicated thread, keeping the tokio runtime available for async handlers.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iceoryx2::prelude::*;
use tracing::{error, info};

use clawlet_core::audit::AuditLogger;
use clawlet_core::config::Config;
use clawlet_core::policy::PolicyEngine;
use clawlet_evm::EvmAdapter;
use clawlet_signer::signer::LocalSigner;

use crate::dispatch;
use crate::types::{RpcRequest, RpcResponse};

/// Default service name used for the iceoryx2 request-response channel.
pub const SERVICE_NAME: &str = "clawlet/rpc";

/// Cycle time for the server polling loop.
const CYCLE_TIME: Duration = Duration::from_millis(10);

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
    /// Signer for transaction execution.
    pub signer: Arc<LocalSigner>,
    /// Skills directory containing AIS specs.
    pub skills_dir: PathBuf,
}

/// RPC server that runs an iceoryx2 request-response service.
pub struct RpcServer;

impl RpcServer {
    /// Start the RPC server using the provided configuration.
    ///
    /// This will:
    /// 1. Load the policy engine from the configured policy file
    /// 2. Create an audit logger at the configured path
    /// 3. Build EVM adapters for each configured chain
    /// 4. Create an iceoryx2 request-response service and process requests
    pub async fn start(
        config: &Config,
        signer: LocalSigner,
    ) -> Result<(), Box<dyn std::error::Error>> {
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
        let skills_dir = std::env::var("CLAWLET_SKILLS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("skills"));

        let state = AppState {
            policy: Arc::new(policy),
            audit: Arc::new(Mutex::new(audit)),
            adapters: Arc::new(adapters),
            auth_token,
            signer: Arc::new(signer),
            skills_dir,
        };

        // Grab a handle to the current tokio runtime so async handlers can be
        // driven from inside the blocking iceoryx2 loop.
        let rt = tokio::runtime::Handle::current();

        info!("starting clawlet-rpc iceoryx2 service: {}", SERVICE_NAME);

        // Run the iceoryx2 loop on a blocking thread so we don't starve the
        // tokio executor.
        tokio::task::spawn_blocking(move || {
            if let Err(e) = run_service_loop(state, rt) {
                error!("iceoryx2 service loop exited with error: {e}");
            }
        })
        .await?;

        Ok(())
    }
}

/// The blocking iceoryx2 service loop.
///
/// Creates a node and request-response service, then polls for incoming
/// requests and dispatches them.
fn run_service_loop(
    state: AppState,
    rt: tokio::runtime::Handle,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let node = NodeBuilder::new()
        .create::<ipc::Service>()
        .map_err(|e| format!("failed to create iceoryx2 node: {e:?}"))?;

    let service = node
        .service_builder(
            &SERVICE_NAME
                .try_into()
                .map_err(|e| format!("invalid service name: {e:?}"))?,
        )
        .request_response::<RpcRequest, RpcResponse>()
        .open_or_create()
        .map_err(|e| format!("failed to create iceoryx2 service: {e:?}"))?;

    let server = service
        .server_builder()
        .create()
        .map_err(|e| format!("failed to create iceoryx2 server: {e:?}"))?;

    info!("clawlet-rpc iceoryx2 server ready, waiting for requests");

    while node.wait(CYCLE_TIME).is_ok() {
        while let Some(active_request) = server
            .receive()
            .map_err(|e| format!("receive error: {e:?}"))?
        {
            let rpc_response = dispatch::dispatch(&state, &active_request, &rt);

            // Send the response back
            match active_request.loan_uninit() {
                Ok(response_slot) => {
                    let response_slot = response_slot.write_payload(rpc_response);
                    if let Err(e) = response_slot.send() {
                        error!("failed to send response: {e:?}");
                    }
                }
                Err(e) => {
                    error!("failed to loan response slot: {e:?}");
                }
            }
        }
    }

    info!("clawlet-rpc iceoryx2 server shutting down");
    Ok(())
}
