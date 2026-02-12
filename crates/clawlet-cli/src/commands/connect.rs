//! `clawlet connect` — one-click wallet connection for OwliaBot.
//!
//! Flow:
//! 1. Prompt admin password via native UI dialog (or terminal fallback)
//! 2. Call auth.grant RPC to get a session token (scope: trade, expires: 7d)
//! 3. Call `owliabot wallet connect` to register the token
//! 4. Print result

use std::net::SocketAddr;

use clawlet_core::auth::TokenScope;
use clawlet_rpc::client::RpcClient;
use clawlet_rpc::server::DEFAULT_ADDR;
use serde::{Deserialize, Serialize};

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
    Ok(s.parse()?)
}

/// Prompt for a password using a native GUI dialog, falling back to terminal.
///
/// - **macOS**: osascript (AppleScript) dialog with hidden input
/// - **Linux**: zenity, then kdialog, then terminal fallback
/// - **Fallback**: rpassword terminal prompt
fn prompt_password_gui() -> Result<String, Box<dyn std::error::Error>> {
    // macOS: use osascript
    if cfg!(target_os = "macos") {
        let output = std::process::Command::new("osascript")
            .args([
                "-e",
                r#"display dialog "请输入钱包管理员密码" with title "Clawlet Connect" default answer "" with hidden answer with icon caution"#,
            ])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                // Output format: "button returned:OK, text returned:PASSWORD"
                if let Some(idx) = stdout.find("text returned:") {
                    let password = stdout[idx + "text returned:".len()..].trim();
                    return Ok(password.to_string());
                }
            }
        }
        // Fall through to terminal fallback
    }

    // Linux: try zenity, then kdialog
    if cfg!(target_os = "linux") {
        if which::which("zenity").is_ok() {
            let output = std::process::Command::new("zenity")
                .args(["--password", "--title=Clawlet Connect"])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    return Ok(password);
                }
            }
        }

        if which::which("kdialog").is_ok() {
            let output = std::process::Command::new("kdialog")
                .args([
                    "--password",
                    "请输入钱包管理员密码",
                    "--title",
                    "Clawlet Connect",
                ])
                .output();

            if let Ok(output) = output {
                if output.status.success() {
                    let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    return Ok(password);
                }
            }
        }
    }

    // Terminal fallback
    let password = rpassword::prompt_password_stderr("管理员密码: ")?;
    Ok(password)
}

/// Create an RPC client with the given server address.
fn create_client(addr: Option<SocketAddr>) -> RpcClient {
    match addr {
        Some(a) => RpcClient::with_addr(&a.to_string()),
        None => RpcClient::with_addr(DEFAULT_ADDR),
    }
}

/// Run the `clawlet connect` command.
pub async fn run(
    addr: Option<SocketAddr>,
    agent: String,
    scope: String,
    expires: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Validate scope
    let _: TokenScope = scope
        .parse()
        .map_err(|_| format!("invalid scope: {scope}. Use 'read', 'trade', or 'admin'"))?;

    // Parse duration
    let expires_hours = parse_duration_hours(&expires)?;

    // Step 1: Prompt for password
    eprintln!("🔐 请输入管理员密码以授权连接...");
    let password = prompt_password_gui()?;

    // Step 2: Call auth.grant RPC
    let req = AuthGrantRequest {
        password,
        agent_id: agent.clone(),
        scope: scope.clone(),
        expires_hours: Some(expires_hours),
    };

    let client = create_client(addr);
    let params = serde_json::to_value(req)?;
    let result = client.call_raw("auth.grant", params).await?;
    let resp: AuthGrantResponse = serde_json::from_value(result)?;

    eprintln!(
        "✅ Token granted (agent: {agent}, scope: {scope}, expires: {})",
        resp.expires_at
    );

    // Step 3: Call owliabot wallet connect
    let server_addr = addr.map_or_else(|| DEFAULT_ADDR.to_string(), |a| a.to_string());
    let clawlet_url = format!("http://{server_addr}");

    if which::which("owliabot").is_ok() {
        eprintln!("🔗 Connecting to OwliaBot...");
        let status = std::process::Command::new("owliabot")
            .args([
                "wallet",
                "connect",
                "--clawlet-url",
                &clawlet_url,
                "--token",
                &resp.token,
            ])
            .status();

        match status {
            Ok(s) if s.success() => {
                eprintln!("✅ OwliaBot 已连接到 clawlet ({clawlet_url})");
            }
            Ok(s) => {
                eprintln!("⚠️  owliabot wallet connect 退出码: {s}");
                eprintln!();
                eprintln!("你可以手动运行:");
                eprintln!("  owliabot wallet connect --clawlet-url {clawlet_url} --token <token>");
                eprintln!();
                eprintln!("Token:");
                println!("{}", resp.token);
            }
            Err(e) => {
                eprintln!("⚠️  无法执行 owliabot: {e}");
                print_manual_instructions(&clawlet_url, &resp.token);
            }
        }
    } else {
        eprintln!("ℹ️  owliabot 不在 PATH 中，请手动连接:");
        print_manual_instructions(&clawlet_url, &resp.token);
    }

    Ok(())
}

fn print_manual_instructions(clawlet_url: &str, token: &str) {
    eprintln!();
    eprintln!("  owliabot wallet connect --clawlet-url {clawlet_url} --token <token>");
    eprintln!();
    eprintln!("Token:");
    println!("{token}");
}
