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

        /// Session duration (e.g., "24h", "7d", "1w").
        #[arg(long, default_value = "24h")]
        expires: String,

        /// Server address (default: 127.0.0.1:9100).
        #[arg(long, short)]
        addr: Option<SocketAddr>,
    },

    /// List all active sessions.
    List {
        /// Server address (default: 127.0.0.1:9100).
        #[arg(long, short)]
        addr: Option<SocketAddr>,
    },

    /// Revoke a session by agent ID.
    Revoke {
        /// Agent identifier to revoke.
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
    expires_hours: Option<u64>,
}

/// Response for auth grant RPC.
#[derive(Deserialize)]
struct AuthGrantResponse {
    token: String,
    expires_at: String,
}

/// Request body for auth list RPC.
#[derive(Serialize)]
struct AuthListRequest {
    password: String,
}

/// Session summary in list response.
#[derive(Deserialize)]
struct SessionSummary {
    id: String,
    scope: String,
    created_at: String,
    expires_at: String,
    last_used_at: String,
    request_count: u64,
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

/// Parse a duration string like "24h", "7d", "1w" into hours.
fn parse_duration_hours(s: &str) -> Result<u64, Box<dyn std::error::Error>> {
    let s = s.trim().to_lowercase();

    if let Some(hours) = s.strip_suffix('h') {
        return Ok(hours.parse()?);
    }
    if let Some(days) = s.strip_suffix('d') {
        return Ok(days.parse::<u64>()? * 24);
    }
    if let Some(weeks) = s.strip_suffix('w') {
        return Ok(weeks.parse::<u64>()? * 24 * 7);
    }

    // Try parsing as plain hours
    Ok(s.parse()?)
}

/// Run an auth subcommand.
pub async fn run(
    cmd: AuthCommand,
    _config_path: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        AuthCommand::Grant {
            agent,
            scope,
            expires,
            addr,
        } => run_grant(agent, scope, expires, addr).await,
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
    let response = client.call_raw(method, params).await?;

    if let Some(error) = response.error {
        return Err(format!("{} (code {})", error.message, error.code).into());
    }

    let result = response.result.ok_or("empty result")?;
    Ok(serde_json::from_value(result)?)
}

/// Grant a new session token.
async fn run_grant(
    agent: String,
    scope: String,
    expires: String,
    addr: Option<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate scope before prompting for password
    let _: TokenScope = scope
        .parse()
        .map_err(|_| format!("invalid scope: {scope}. Use 'read', 'trade', or 'admin'"))?;

    // Parse duration
    let expires_hours = parse_duration_hours(&expires)?;

    // Prompt for password
    eprint!("Enter admin password: ");
    let password = rpassword::read_password()?;

    // Build request
    let req = AuthGrantRequest {
        password,
        agent_id: agent.clone(),
        scope: scope.clone(),
        expires_hours: Some(expires_hours),
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
    eprintln!("Expires: {}", resp.expires_at);

    Ok(())
}

/// List all active sessions.
async fn run_list(addr: Option<SocketAddr>) -> Result<(), Box<dyn std::error::Error>> {
    // Prompt for password
    eprint!("Enter admin password: ");
    let password = rpassword::read_password()?;

    // Build request
    let req = AuthListRequest { password };

    // Create client and send request
    let client = create_client(addr);
    let resp: AuthListResponse = send_request(&client, "auth.list", req).await?;

    eprintln!();
    if resp.sessions.is_empty() {
        eprintln!("No active sessions.");
    } else {
        eprintln!("Active sessions:");
        eprintln!();
        for session in &resp.sessions {
            eprintln!("  Agent: {}", session.id);
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

/// Revoke a session by agent ID.
async fn run_revoke(
    agent: String,
    addr: Option<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prompt for password
    eprint!("Enter admin password: ");
    let password = rpassword::read_password()?;

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
        eprintln!("✅ Session revoked for agent: {agent}");
    } else {
        eprintln!("⚠️  No active session found for agent: {agent}");
    }

    Ok(())
}

/// Revoke all sessions.
async fn run_revoke_all(addr: Option<SocketAddr>) -> Result<(), Box<dyn std::error::Error>> {
    // Prompt for password
    eprint!("Enter admin password: ");
    let password = rpassword::read_password()?;

    // Confirm
    eprint!("Are you sure you want to revoke ALL sessions? [y/N]: ");
    let mut confirm = String::new();
    std::io::stdin().read_line(&mut confirm)?;
    if !confirm.trim().eq_ignore_ascii_case("y") {
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
