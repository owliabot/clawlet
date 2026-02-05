//! `clawlet auth` — session management commands.
//!
//! Allows humans to grant, list, and revoke session tokens for AI agents.
//! All commands require password authentication.

use std::path::PathBuf;

use clap::Subcommand;
use clawlet_core::auth::TokenScope;
use clawlet_ipc::client::RpcClient;
use clawlet_ipc::types::RpcMethod;
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
    },

    /// List all active sessions.
    List,

    /// Revoke a session by agent ID.
    Revoke {
        /// Agent identifier to revoke.
        #[arg(long)]
        agent: String,
    },

    /// Revoke all active sessions.
    RevokeAll,
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
pub fn run(
    cmd: AuthCommand,
    config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        AuthCommand::Grant {
            agent,
            scope,
            expires,
        } => run_grant(agent, scope, expires, config_path),
        AuthCommand::List => run_list(config_path),
        AuthCommand::Revoke { agent } => run_revoke(agent, config_path),
        AuthCommand::RevokeAll => run_revoke_all(config_path),
    }
}

/// Grant a new session token.
fn run_grant(
    agent: String,
    scope: String,
    expires: String,
    _config_path: Option<PathBuf>,
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

    let payload = serde_json::to_vec(&req)?;

    // Create client and send request
    let client = RpcClient::new()?;
    let response = client.call(RpcMethod::AuthGrant, "", &payload)?;

    if !response.is_ok() {
        let error: serde_json::Value = serde_json::from_slice(response.payload_bytes())?;
        let msg = error
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(format!("Failed to grant session: {msg}").into());
    }

    let resp: AuthGrantResponse = serde_json::from_slice(response.payload_bytes())?;

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
fn run_list(_config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    // Prompt for password
    eprint!("Enter admin password: ");
    let password = rpassword::read_password()?;

    // Build request
    let req = AuthListRequest { password };
    let payload = serde_json::to_vec(&req)?;

    // Create client and send request
    let client = RpcClient::new()?;
    let response = client.call(RpcMethod::AuthList, "", &payload)?;

    if !response.is_ok() {
        let error: serde_json::Value = serde_json::from_slice(response.payload_bytes())?;
        let msg = error
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(format!("Failed to list sessions: {msg}").into());
    }

    let resp: AuthListResponse = serde_json::from_slice(response.payload_bytes())?;

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
fn run_revoke(
    agent: String,
    _config_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prompt for password
    eprint!("Enter admin password: ");
    let password = rpassword::read_password()?;

    // Build request
    let req = AuthRevokeRequest {
        password,
        agent_id: agent.clone(),
    };
    let payload = serde_json::to_vec(&req)?;

    // Create client and send request
    let client = RpcClient::new()?;
    let response = client.call(RpcMethod::AuthRevoke, "", &payload)?;

    if !response.is_ok() {
        let error: serde_json::Value = serde_json::from_slice(response.payload_bytes())?;
        let msg = error
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(format!("Failed to revoke session: {msg}").into());
    }

    let resp: AuthRevokeResponse = serde_json::from_slice(response.payload_bytes())?;

    eprintln!();
    if resp.revoked {
        eprintln!("✅ Session revoked for agent: {agent}");
    } else {
        eprintln!("⚠️  No active session found for agent: {agent}");
    }

    Ok(())
}

/// Revoke all sessions.
fn run_revoke_all(_config_path: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
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
    let payload = serde_json::to_vec(&req)?;

    // Create client and send request
    let client = RpcClient::new()?;
    let response = client.call(RpcMethod::AuthRevokeAll, "", &payload)?;

    if !response.is_ok() {
        let error: serde_json::Value = serde_json::from_slice(response.payload_bytes())?;
        let msg = error
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(format!("Failed to revoke sessions: {msg}").into());
    }

    let resp: AuthRevokeAllResponse = serde_json::from_slice(response.payload_bytes())?;

    eprintln!();
    eprintln!("✅ Revoked {} session(s)", resp.count);

    Ok(())
}
