//! `clawlet connect` — one-click wallet connection for OwliaBot.
//!
//! Flow:
//! 1. Prompt admin password via native UI dialog (or terminal fallback)
//! 2. Call auth.grant RPC to get a session token (scope: trade, expires: 7d)
//! 3. Call `owliabot wallet connect` to register the token
//! 4. Print result

use std::net::SocketAddr;
use std::time::Duration;

use clawlet_core::auth::TokenScope;
use clawlet_rpc::client::RpcClient;
use clawlet_rpc::server::DEFAULT_ADDR;
use serde::{Deserialize, Serialize};
use tokio::time::timeout;

/// Timeout for GUI password dialogs. If no response within this duration,
/// the dialog process is killed and we fall back to terminal input.
const DIALOG_TIMEOUT: Duration = Duration::from_secs(120);

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
///
/// GUI dialogs are spawned with `kill_on_drop(true)` and wrapped in a timeout
/// to prevent the process from hanging indefinitely when no GUI session is
/// available or the window server is unreachable.
async fn prompt_password_gui() -> Result<String, Box<dyn std::error::Error>> {
    // macOS: use osascript
    if cfg!(target_os = "macos") {
        let child = tokio::process::Command::new("osascript")
            .args([
                "-e",
                r#"display dialog "请输入钱包管理员密码" with title "Clawlet Connect" default answer "" with hidden answer with icon caution"#,
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn();

        if let Ok(child) = child {
            match timeout(DIALOG_TIMEOUT, child.wait_with_output()).await {
                Ok(Ok(output)) if output.status.success() => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    // Output format: "button returned:OK, text returned:PASSWORD"
                    if let Some(idx) = stdout.find("text returned:") {
                        let password = stdout[idx + "text returned:".len()..].trim();
                        return Ok(password.to_string());
                    }
                }
                Err(_) => {
                    eprintln!("⚠️  密码对话框超时，回退到终端输入");
                }
                _ => {}
            }
        }
        // Fall through to terminal fallback
    }

    // Linux: try zenity, then kdialog
    if cfg!(target_os = "linux") {
        if which::which("zenity").is_ok() {
            let child = tokio::process::Command::new("zenity")
                .args(["--password", "--title=Clawlet Connect"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn();

            if let Ok(child) = child {
                match timeout(DIALOG_TIMEOUT, child.wait_with_output()).await {
                    Ok(Ok(output)) if output.status.success() => {
                        let password =
                            String::from_utf8_lossy(&output.stdout).trim().to_string();
                        return Ok(password);
                    }
                    Err(_) => {
                        eprintln!("⚠️  密码对话框超时，回退到终端输入");
                    }
                    _ => {}
                }
            }
        }

        if which::which("kdialog").is_ok() {
            let child = tokio::process::Command::new("kdialog")
                .args([
                    "--password",
                    "请输入钱包管理员密码",
                    "--title",
                    "Clawlet Connect",
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .spawn();

            if let Ok(child) = child {
                match timeout(DIALOG_TIMEOUT, child.wait_with_output()).await {
                    Ok(Ok(output)) if output.status.success() => {
                        let password =
                            String::from_utf8_lossy(&output.stdout).trim().to_string();
                        return Ok(password);
                    }
                    Err(_) => {
                        eprintln!("⚠️  密码对话框超时，回退到终端输入");
                    }
                    _ => {}
                }
            }
        }
    }

    // Terminal fallback
    let password =
        tokio::task::spawn_blocking(|| rpassword::prompt_password_stderr("管理员密码: "))
            .await??;
    Ok(password)
}

/// Detected OwliaBot runtime environment.
enum OwliabotRuntime {
    /// Binary found in PATH.
    Binary,
    /// Running in a Docker container.
    Docker(String),
    /// Available via npx.
    Npx,
}

/// Detect how OwliaBot is running. Priority: PATH > Docker > npx.
fn detect_owliabot_runtime() -> Option<OwliabotRuntime> {
    // 1. Direct binary in PATH
    if which::which("owliabot").is_ok() {
        return Some(OwliabotRuntime::Binary);
    }

    // 2. Running Docker container named "owliabot"
    if which::which("docker").is_ok() {
        if let Ok(output) = std::process::Command::new("docker")
            .args(["ps", "--filter", "name=owliabot", "--format", "{{.Names}}"])
            .output()
        {
            let names = String::from_utf8_lossy(&output.stdout);
            if let Some(container) = names.lines().next().filter(|s| !s.is_empty()) {
                return Some(OwliabotRuntime::Docker(container.to_string()));
            }
        }
    }

    // 3. npx available
    if which::which("npx").is_ok() {
        return Some(OwliabotRuntime::Npx);
    }

    None
}

/// Build the command to invoke `owliabot wallet connect` for the given runtime.
fn build_owliabot_command(
    runtime: &OwliabotRuntime,
    clawlet_url: &str,
    token: &str,
) -> std::process::Command {
    let wallet_args = ["wallet", "connect", "--base-url", clawlet_url, "--token", token];
    match runtime {
        OwliabotRuntime::Binary => {
            let mut cmd = std::process::Command::new("owliabot");
            cmd.args(wallet_args);
            cmd
        }
        OwliabotRuntime::Docker(container) => {
            let mut cmd = std::process::Command::new("docker");
            cmd.args(["exec", container, "owliabot"]);
            cmd.args(wallet_args);
            cmd
        }
        OwliabotRuntime::Npx => {
            let mut cmd = std::process::Command::new("npx");
            cmd.args(["owliabot"]);
            cmd.args(wallet_args);
            cmd
        }
    }
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
    let password = prompt_password_gui().await?;

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

    match detect_owliabot_runtime() {
        Some(runtime) => {
            let label = match &runtime {
                OwliabotRuntime::Binary => "owliabot (PATH)".to_string(),
                OwliabotRuntime::Docker(c) => format!("docker exec {c}"),
                OwliabotRuntime::Npx => "npx owliabot".to_string(),
            };
            eprintln!("🔗 Connecting to OwliaBot via {label}...");

            let status = build_owliabot_command(&runtime, &clawlet_url, &resp.token).status();

            match status {
                Ok(s) if s.success() => {
                    eprintln!("✅ OwliaBot 已连接到 clawlet ({clawlet_url})");
                }
                Ok(s) => {
                    eprintln!("⚠️  owliabot wallet connect 退出码: {s}");
                    eprintln!();
                    eprintln!("你可以手动运行:");
                    print_manual_instructions(&clawlet_url, &resp.token);
                }
                Err(e) => {
                    eprintln!("⚠️  无法执行 owliabot: {e}");
                    print_manual_instructions(&clawlet_url, &resp.token);
                }
            }
        }
        None => {
            eprintln!("ℹ️  未检测到 owliabot (PATH / Docker / npx)，请手动连接:");
            print_manual_instructions(&clawlet_url, &resp.token);
        }
    }

    Ok(())
}

fn print_manual_instructions(clawlet_url: &str, token: &str) {
    eprintln!();
    eprintln!("  # 直接运行:");
    eprintln!("  owliabot wallet connect --base-url {clawlet_url} --token <token>");
    eprintln!();
    eprintln!("  # 或通过 Docker:");
    eprintln!("  docker exec owliabot owliabot wallet connect --base-url {clawlet_url} --token <token>");
    eprintln!();
    eprintln!("  # 或通过 npx:");
    eprintln!("  npx owliabot wallet connect --base-url {clawlet_url} --token <token>");
    eprintln!();
    eprintln!("Token:");
    println!("{token}");
}
