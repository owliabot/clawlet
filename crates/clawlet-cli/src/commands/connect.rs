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
                r#"display dialog "请输入钱包管理员密码 (Enter admin password)" with title "Clawlet Connect" default answer "" with hidden answer with icon caution"#,
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
                    eprintln!("⚠️  密码对话框超时，回退到终端输入 (Dialog timed out, falling back to terminal)");
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
                        let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        return Ok(password);
                    }
                    Err(_) => {
                        eprintln!("⚠️  密码对话框超时，回退到终端输入 (Dialog timed out, falling back to terminal)");
                    }
                    _ => {}
                }
            }
        }

        if which::which("kdialog").is_ok() {
            let child = tokio::process::Command::new("kdialog")
                .args([
                    "--password",
                    "请输入钱包管理员密码 (Enter admin password)",
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
                        let password = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        return Ok(password);
                    }
                    Err(_) => {
                        eprintln!("⚠️  密码对话框超时，回退到终端输入 (Dialog timed out, falling back to terminal)");
                    }
                    _ => {}
                }
            }
        }
    }

    // Terminal fallback
    let password = tokio::task::spawn_blocking(|| {
        rpassword::prompt_password_stderr("管理员密码 (Admin password): ")
    })
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

/// Run `owliabot wallet connect` for the given runtime.
///
/// The token is passed via environment variable or stdin pipe rather than
/// command-line arguments to prevent exposure in `ps` output.
fn run_owliabot_command(
    runtime: &OwliabotRuntime,
    token: &str,
) -> std::io::Result<std::process::ExitStatus> {
    // Don't pass --base-url; owliabot resolves the clawlet endpoint via its
    // own config. This avoids Docker networking issues where 127.0.0.1 inside
    // a container doesn't reach the host.
    match runtime {
        OwliabotRuntime::Binary => std::process::Command::new("sh")
            .env("_CLAWLET_TOKEN", token)
            .args(["-c", "owliabot wallet connect --token \"$_CLAWLET_TOKEN\""])
            .status(),
        OwliabotRuntime::Docker(container) => {
            let mut child = std::process::Command::new("docker")
                .args([
                    "exec",
                    "-i",
                    container,
                    "sh",
                    "-c",
                    "read _TOKEN && owliabot wallet connect --token \"$_TOKEN\"",
                ])
                .stdin(std::process::Stdio::piped())
                .spawn()?;
            if let Some(mut stdin) = child.stdin.take() {
                use std::io::Write;
                writeln!(stdin, "{}", token)?;
            }
            child.wait()
        }
        OwliabotRuntime::Npx => std::process::Command::new("sh")
            .env("_CLAWLET_TOKEN", token)
            .args([
                "-c",
                "npx owliabot wallet connect --token \"$_CLAWLET_TOKEN\"",
            ])
            .status(),
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

    // Warn if target is not localhost — password and token travel over plaintext HTTP
    if let Some(a) = addr {
        if !a.ip().is_loopback() {
            eprintln!("⚠️  警告 (Warning): 目标地址 {a} 不是 localhost，密码和 token 将通过未加密的 HTTP 传输！");
            eprintln!("   (Address {a} is not localhost — password and token will be sent over unencrypted HTTP!)");
            eprintln!(
                "   建议通过 SSH 隧道连接 (Recommended: use SSH tunnel): ssh -L 9100:{a} user@host"
            );
            eprintln!();
        }
    }

    // Step 1: Prompt for password
    eprintln!("🔐 请输入管理员密码以授权连接 (Enter admin password to authorize connection)...");
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
        "✅ 令牌已授予 (Token granted) — agent: {agent}, scope: {scope}, expires: {}",
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
            eprintln!("🔗 正在连接 OwliaBot (Connecting to OwliaBot via {label})...");
            let status = run_owliabot_command(&runtime, &resp.token);

            match status {
                Ok(s) if s.success() => {
                    eprintln!("✅ OwliaBot 已连接到 clawlet (Connected to {clawlet_url})");
                }
                Ok(s) => {
                    eprintln!("⚠️  owliabot wallet connect 退出码 (exit code): {s}");
                    print_manual_instructions(&resp.token);
                    return Err(
                        format!("owliabot wallet connect failed with exit code: {s}").into(),
                    );
                }
                Err(e) => {
                    eprintln!("⚠️  无法执行 (Failed to execute): {e}");
                    print_manual_instructions(&resp.token);
                    return Err(format!("failed to execute owliabot wallet connect: {e}").into());
                }
            }
        }
        None => {
            eprintln!("ℹ️  未检测到 owliabot (Not found in PATH / Docker / npx)，请手动连接 (connect manually):");
            print_manual_instructions(&resp.token);
        }
    }

    Ok(())
}

fn print_manual_instructions(token: &str) {
    eprintln!();
    eprintln!("  # 直接运行 (Run directly):");
    eprintln!("  _CLAWLET_TOKEN='<token>' owliabot wallet connect --token \"$_CLAWLET_TOKEN\"");
    eprintln!();
    eprintln!("  # 或通过 Docker (Or via Docker):");
    eprintln!("  echo '<token>' | docker exec -i owliabot sh -c 'read T && owliabot wallet connect --token \"$T\"'");
    eprintln!();
    eprintln!("  # 或通过 npx (Or via npx):");
    eprintln!("  _CLAWLET_TOKEN='<token>' npx owliabot wallet connect --token \"$_CLAWLET_TOKEN\"");
    eprintln!();
    eprintln!("Token (使用后请清除终端历史 / clear terminal history after use):");
    println!("{token}");
}
