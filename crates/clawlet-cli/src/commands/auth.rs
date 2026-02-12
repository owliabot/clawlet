//! `clawlet auth` — session management commands.
//!
//! Allows humans to grant, list, and revoke session tokens for AI agents.
//! All commands require password authentication.

use std::net::SocketAddr;

use clap::Subcommand;
use clawlet_core::auth::TokenScope;
use clawlet_rpc::client::RpcClient;
use clawlet_rpc::server::DEFAULT_ADDR;
use serde::{Deserialize, Serialize};

/// Auth subcommands.
#[derive(Subcommand)]
pub enum AuthCommand {
    /// Grant a new session token to an agent.
    Grant {
        /// Agent identifier (e.g., "openclaw-main").
        #[arg(long)]
        agent: String,

        /// Permission scope: read, trade, or admin.
        #[arg(long, default_value = "trade")]
        scope: String,

        /// Server address (default: 127.0.0.1:9100).
        #[arg(long, short)]
        addr: Option<SocketAddr>,
    },

    /// List all sessions (including expired ones in grace period).
    List {
        /// Server address (default: 127.0.0.1:9100).
        #[arg(long, short)]
        addr: Option<SocketAddr>,
    },

    /// Revoke all sessions for an agent.
    Revoke {
        /// Agent identifier whose sessions should all be revoked.
        #[arg(long)]
        agent: String,

        /// Server address (default: 127.0.0.1:9100).
        #[arg(long, short)]
        addr: Option<SocketAddr>,
    },

    /// Revoke all active sessions.
    RevokeAll {
        /// Server address (default: 127.0.0.1:9100).
        #[arg(long, short)]
        addr: Option<SocketAddr>,
    },
}

/// Request body for auth grant RPC.
#[derive(Serialize)]
struct AuthGrantRequest {
    password: String,
    agent_id: String,
    scope: String,
}

/// Response for auth grant RPC.
#[derive(Deserialize)]
struct AuthGrantResponse {
    token: String,
}

/// Request body for auth list RPC.
#[derive(Serialize)]
struct AuthListRequest {
    password: String,
}

/// Session summary in list response.
#[derive(Deserialize)]
struct SessionSummary {
    session_key: String,
    id: String,
    scope: String,
    created_at: String,
    expires_at: String,
    last_used_at: String,
    request_count: u64,
    is_expired: bool,
}

/// Response for auth list RPC.
#[derive(Deserialize)]
struct AuthListResponse {
    sessions: Vec<SessionSummary>,
}

/// Request body for auth revoke RPC.
#[derive(Serialize)]
struct AuthRevokeRequest {
    password: String,
    agent_id: String,
}

/// Response for auth revoke RPC.
#[derive(Deserialize)]
struct AuthRevokeResponse {
    revoked: bool,
}

/// Request body for auth revoke all RPC.
#[derive(Serialize)]
struct AuthRevokeAllRequest {
    password: String,
}

/// Response for auth revoke all RPC.
#[derive(Deserialize)]
struct AuthRevokeAllResponse {
    count: usize,
}

/// Run an auth subcommand.
pub async fn run(
    cmd: AuthCommand,
    _config_path: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        AuthCommand::Grant { agent, scope, addr } => run_grant(agent, scope, addr).await,
        AuthCommand::List { addr } => run_list(addr).await,
        AuthCommand::Revoke { agent, addr } => run_revoke(agent, addr).await,
        AuthCommand::RevokeAll { addr } => run_revoke_all(addr).await,
    }
}

/// Create an RPC client with the given server address.
fn create_client(addr: Option<SocketAddr>) -> RpcClient {
    match addr {
        Some(a) => RpcClient::with_addr(&a.to_string()),
        None => RpcClient::with_addr(DEFAULT_ADDR),
    }
}

/// Send a JSON-RPC request and get the response.
async fn send_request<R: for<'de> Deserialize<'de>>(
    client: &RpcClient,
    method: &str,
    params: impl Serialize,
) -> Result<R, Box<dyn std::error::Error>> {
    let params = serde_json::to_value(params)?;
    let result = client.call_raw(method, params).await?;
    Ok(serde_json::from_value(result)?)
}

/// Grant a new session token.
async fn run_grant(
    agent: String,
    scope: String,
    addr: Option<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate scope before prompting for password
    let _: TokenScope = scope
        .parse()
        .map_err(|_| format!("invalid scope: {scope}. Use 'read', 'trade', or 'admin'"))?;

    // Prompt for password
    let password = super::read_password("Enter wallet password: ", "CLAWLET_PASSWORD")?;

    // Build request
    let req = AuthGrantRequest {
        password,
        agent_id: agent.clone(),
        scope: scope.clone(),
    };

    // Create client and send request
    let client = create_client(addr);
    let resp: AuthGrantResponse = send_request(&client, "auth.grant", req).await?;

    eprintln!();
    eprintln!("✅ Session granted to agent: {agent}");
    eprintln!();
    eprintln!("Token (copy this — it will NOT be shown again):");
    eprintln!();
    println!("{}", resp.token);
    eprintln!();
    eprintln!("Scope: {scope}");
    eprintln!("Expires: never");

    Ok(())
}

/// List all active sessions.
async fn run_list(addr: Option<SocketAddr>) -> Result<(), Box<dyn std::error::Error>> {
    // Prompt for password
    let password = super::read_password("Enter wallet password: ", "CLAWLET_PASSWORD")?;

    // Build request
    let req = AuthListRequest { password };

    // Create client and send request
    let client = create_client(addr);
    let resp: AuthListResponse = send_request(&client, "auth.list", req).await?;

    eprintln!();
    if resp.sessions.is_empty() {
        eprintln!("No sessions.");
    } else {
        eprintln!("Sessions:");
        eprintln!();
        for session in &resp.sessions {
            let status = if session.is_expired { " [EXPIRED]" } else { "" };
            eprintln!("  Agent: {}{}", session.id, status);
            eprintln!("    Session key: {}", session.session_key);
            eprintln!("    Scope: {}", session.scope);
            eprintln!("    Created: {}", session.created_at);
            eprintln!("    Expires: {}", session.expires_at);
            eprintln!("    Last used: {}", session.last_used_at);
            eprintln!("    Requests: {}", session.request_count);
            eprintln!();
        }
    }

    Ok(())
}

/// Revoke all sessions for an agent.
async fn run_revoke(
    agent: String,
    addr: Option<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prompt for password
    let password = super::read_password("Enter wallet password: ", "CLAWLET_PASSWORD")?;

    // Build request
    let req = AuthRevokeRequest {
        password,
        agent_id: agent.clone(),
    };

    // Create client and send request
    let client = create_client(addr);
    let resp: AuthRevokeResponse = send_request(&client, "auth.revoke", req).await?;

    eprintln!();
    if resp.revoked {
        eprintln!("✅ All sessions revoked for agent: {agent}");
    } else {
        eprintln!("⚠️  No sessions found for agent: {agent}");
    }

    Ok(())
}

/// Revoke all sessions.
async fn run_revoke_all(addr: Option<SocketAddr>) -> Result<(), Box<dyn std::error::Error>> {
    // Prompt for password
    let password = super::read_password("Enter wallet password: ", "CLAWLET_PASSWORD")?;

    // Confirm
    eprint!("Are you sure you want to revoke ALL sessions? [y/N]: ");
    let confirm = super::read_line_or_default("n")?;
    if !confirm.eq_ignore_ascii_case("y") {
        eprintln!("Cancelled.");
        return Ok(());
    }

    // Build request
    let req = AuthRevokeAllRequest { password };

    // Create client and send request
    let client = create_client(addr);
    let resp: AuthRevokeAllResponse = send_request(&client, "auth.revoke_all", req).await?;

    eprintln!();
    eprintln!("✅ Revoked {} session(s)", resp.count);

    Ok(())
}
