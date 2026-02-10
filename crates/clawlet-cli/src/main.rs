//! # clawlet CLI
//!
//! Entry point for the `clawlet` binary.
//!
//! Subcommands:
//! - `clawlet init`  — Generate keystore and default policy
//! - `clawlet serve` — Start the RPC server
//! - `clawlet auth`  — Manage session tokens for AI agents
//! - `clawlet start` — Quick start: init + auth grant + serve

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};

mod commands;

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

/// Clawlet — lightweight EVM wallet daemon with policy guardrails.
#[derive(Parser)]
#[command(name = "clawlet", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new clawlet instance (keystore, config, policy).
    Init {
        /// Restore from an existing BIP-39 mnemonic instead of generating a new one.
        #[arg(long)]
        from_mnemonic: bool,

        /// Data directory (default: ~/.clawlet).
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// Start the HTTP JSON-RPC server.
    Serve {
        /// Path to config.yaml (default: ~/.clawlet/config.yaml).
        #[arg(long, short)]
        config: Option<PathBuf>,

        /// Address to bind the HTTP server (default: 127.0.0.1:9100).
        #[arg(long, short)]
        addr: Option<SocketAddr>,

        /// Detach and run as a background daemon after password input.
        #[arg(long, short)]
        daemon: bool,
    },

    /// Manage session tokens for AI agents.
    Auth {
        /// Path to config.yaml (default: ~/.clawlet/config.yaml).
        #[arg(long, short)]
        config: Option<PathBuf>,

        #[command(subcommand)]
        command: commands::auth::AuthCommand,
    },

    /// Send ETH or ERC-20 tokens via the running clawlet RPC server.
    Transfer {
        /// Recipient address (0x...).
        #[arg(long)]
        to: String,

        /// Human-readable amount (e.g. "0.1" for 0.1 ETH).
        #[arg(long)]
        amount: rust_decimal::Decimal,

        /// Bearer auth token (or set CLAWLET_AUTH_TOKEN env var).
        #[arg(long, env = "CLAWLET_AUTH_TOKEN")]
        auth_token: String,

        /// Asset to transfer: "ETH" or ERC-20 contract address (default: ETH).
        #[arg(long, default_value = "ETH")]
        asset: clawlet_rpc::types::TokenSpec,

        /// Chain ID override (default: 1).
        #[arg(long)]
        chain_id: Option<u64>,

        /// RPC server address (default: 127.0.0.1:9100).
        #[arg(long)]
        addr: Option<String>,
    },

    /// Send a raw transaction (bypasses policy engine).
    Send {
        /// Recipient address (0x...).
        #[arg(long)]
        to: alloy::primitives::Address,

        /// ETH value to send as raw wei (U256). Default: 0.
        #[arg(long)]
        value: Option<alloy::primitives::U256>,

        /// Hex-encoded calldata (with or without 0x prefix).
        #[arg(long)]
        data: Option<String>,

        /// Chain ID (default: 1).
        #[arg(long)]
        chain_id: Option<u64>,

        /// Gas limit override.
        #[arg(long)]
        gas_limit: Option<u64>,

        /// Bearer auth token (or set CLAWLET_AUTH_TOKEN env var).
        #[arg(long, env = "CLAWLET_AUTH_TOKEN")]
        auth_token: String,

        /// RPC server address (default: 127.0.0.1:9100).
        #[arg(long)]
        addr: Option<String>,
    },

    /// Quick start: init (if needed) + grant token + serve.
    Start {
        /// Agent identifier to grant token to.
        #[arg(long)]
        agent: String,

        /// Token scope: read, trade, or admin (default: trade).
        #[arg(long, default_value = "trade")]
        scope: String,

        /// Token expiry duration (default: 24h).
        #[arg(long, default_value = "24h")]
        expires: String,

        /// Data directory (default: ~/.clawlet).
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Address to bind the HTTP server (default: 127.0.0.1:9100).
        #[arg(long, short)]
        addr: Option<SocketAddr>,

        /// Detach and run as a background daemon after password input.
        #[arg(long, short)]
        daemon: bool,
    },
}

// ---------------------------------------------------------------------------
// Daemon helpers
// ---------------------------------------------------------------------------

/// Fork the current process into a background daemon.
///
/// - Opens `log_path` for append (stdout/stderr are redirected there).
/// - The **parent** prints a status message and exits successfully.
/// - The **child** calls `setsid`, writes its PID to `pid_path`, closes
///   stdin, and returns so the caller can continue with server startup.
#[cfg(unix)]
fn daemonize(log_path: &Path, pid_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fn write_pipe_all(fd: i32, bytes: &[u8]) {
        let mut off = 0usize;
        while off < bytes.len() {
            let n = unsafe {
                libc::write(
                    fd,
                    bytes[off..].as_ptr().cast(),
                    (bytes.len() - off) as libc::size_t,
                )
            };
            if n > 0 {
                off += n as usize;
                continue;
            }
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
    }

    // Open log file *before* forking so both parent and child see any error.
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|e| format!("failed to open log file {}: {e}", log_path.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        log_file
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set log file permissions: {e}"))?;
    }

    // Create a pipe so the child can signal startup success/failure to the parent.
    let mut pipe_fds = [0i32; 2];
    if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } != 0 {
        return Err("pipe() failed".into());
    }
    let (pipe_read, pipe_write) = (pipe_fds[0], pipe_fds[1]);

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err("fork() failed".into());
    }
    if pid > 0 {
        // Parent — wait for the child to signal readiness.
        unsafe { libc::close(pipe_write) };
        let mut msg = Vec::<u8>::new();
        let mut buf = [0u8; 256];
        loop {
            let n = unsafe { libc::read(pipe_read, buf.as_mut_ptr().cast(), buf.len()) };
            if n > 0 {
                msg.extend_from_slice(&buf[..(n as usize)]);
                continue;
            }
            break;
        }
        unsafe { libc::close(pipe_read) };
        let msg = String::from_utf8_lossy(&msg);
        let msg = msg.trim();
        if msg == "ok" {
            eprintln!("Daemon started (PID {pid}), log: {}", log_path.display());
            std::process::exit(0);
        } else {
            if let Some(rest) = msg.strip_prefix("err:") {
                eprintln!("Daemon failed to start: {}", rest.trim());
            }
            eprintln!(
                "Daemon child failed to start; check log: {}",
                log_path.display()
            );
            std::process::exit(1);
        }
    }

    // --- child ---
    unsafe { libc::close(pipe_read) };

    // New session so we detach from the controlling terminal.
    if unsafe { libc::setsid() } < 0 {
        write_pipe_all(pipe_write, b"err: setsid() failed\n");
        unsafe { libc::close(pipe_write) };
        return Err("setsid() failed".into());
    }

    // Write PID file.
    if let Err(e) = std::fs::write(pid_path, format!("{}", std::process::id())) {
        write_pipe_all(
            pipe_write,
            format!(
                "err: failed to write pid file {}: {e}\n",
                pid_path.display()
            )
            .as_bytes(),
        );
        unsafe { libc::close(pipe_write) };
        return Err(e.into());
    }
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(pid_path, std::fs::Permissions::from_mode(0o600)) {
            write_pipe_all(
                pipe_write,
                format!(
                    "err: failed to set pid file permissions {}: {e}\n",
                    pid_path.display()
                )
                .as_bytes(),
            );
            unsafe { libc::close(pipe_write) };
            return Err(e.into());
        }
    }

    // Redirect stdout & stderr to the log file; close stdin.
    let fd = log_file.as_raw_fd();
    unsafe {
        if libc::dup2(fd, libc::STDOUT_FILENO) < 0 {
            write_pipe_all(pipe_write, b"err: dup2(stdout) failed\n");
            libc::close(pipe_write);
            return Err("dup2(stdout) failed".into());
        }
        if libc::dup2(fd, libc::STDERR_FILENO) < 0 {
            write_pipe_all(pipe_write, b"err: dup2(stderr) failed\n");
            libc::close(pipe_write);
            return Err("dup2(stderr) failed".into());
        }
        libc::close(libc::STDIN_FILENO);
    }

    // Signal the parent that child startup succeeded.
    unsafe {
        write_pipe_all(pipe_write, b"ok\n");
        libc::close(pipe_write);
    }

    Ok(())
}

#[cfg(not(unix))]
fn daemonize(_log_path: &Path, _pid_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Err("--daemon is only supported on Unix targets".into())
}

/// Derive the data directory from the config's keystore path.
///
/// `config.keystore_path` is typically `{data_dir}/keystore`, so its parent
/// is the data directory.
fn data_dir_from_config(config: &clawlet_core::config::Config) -> &Path {
    config.keystore_path.parent().unwrap_or(Path::new("."))
}

/// Daemon path for `serve --daemon`.
fn run_serve_daemon(
    config: Option<PathBuf>,
    addr: Option<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let prepared = commands::serve::prepare(config, addr)?;

    let data_dir = data_dir_from_config(&prepared.config);
    let log_path = data_dir.join("clawlet.log");
    let pid_path = data_dir.join("clawlet.pid");

    eprintln!(
        "Clawlet RPC server listening on http://{}",
        prepared.listen_addr
    );
    daemonize(&log_path, &pid_path)?;

    // Child: init tracing (writes to redirected stderr → log file).
    tracing_subscriber::fmt::init();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(commands::serve::start(prepared))
}

/// Daemon path for `start --daemon`.
fn run_start_daemon(
    agent: String,
    scope: String,
    expires: String,
    data_dir: Option<PathBuf>,
    addr: Option<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    let prepared = commands::start::prepare(agent, scope, expires, data_dir, addr)?;

    let dd = data_dir_from_config(&prepared.config);
    let log_path = dd.join("clawlet.log");
    let pid_path = dd.join("clawlet.pid");

    eprintln!(
        "Clawlet RPC server listening on http://{}",
        prepared.listen_addr
    );
    daemonize(&log_path, &pid_path)?;

    tracing_subscriber::fmt::init();

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(commands::start::start(prepared))
}

// ---------------------------------------------------------------------------
// Normal (foreground) async entry point
// ---------------------------------------------------------------------------

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Init {
            from_mnemonic,
            data_dir,
        } => commands::init::run(from_mnemonic, data_dir),
        Commands::Serve { config, addr, .. } => commands::serve::run(config, addr).await,
        Commands::Transfer {
            to,
            amount,
            auth_token,
            asset,
            chain_id,
            addr,
        } => commands::transfer::run(to, amount, asset, chain_id, addr, auth_token).await,
        Commands::Send {
            to,
            value,
            data,
            chain_id,
            gas_limit,
            auth_token,
            addr,
        } => commands::send::run(to, value, data, chain_id, gas_limit, addr, auth_token).await,
        Commands::Auth { config, command } => commands::auth::run(command, config).await,
        Commands::Start {
            agent,
            scope,
            expires,
            data_dir,
            addr,
            ..
        } => commands::start::run(agent, scope, expires, data_dir, addr).await,
    }
}

// ---------------------------------------------------------------------------
// main — no #[tokio::main] so daemon mode can fork before worker threads.
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();

    // Daemon mode: synchronous prepare → fork → create tokio runtime → start.
    // This avoids forking inside an existing multi-threaded tokio runtime.
    let daemon_result = match &cli.command {
        Commands::Serve {
            config,
            addr,
            daemon: true,
        } => Some(run_serve_daemon(config.clone(), *addr)),
        Commands::Start {
            agent,
            scope,
            expires,
            data_dir,
            addr,
            daemon: true,
        } => Some(run_start_daemon(
            agent.clone(),
            scope.clone(),
            expires.clone(),
            data_dir.clone(),
            *addr,
        )),
        _ => None,
    };

    if let Some(result) = daemon_result {
        if let Err(e) = result {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        return;
    }

    // Normal foreground mode: init tracing, create runtime, dispatch.
    tracing_subscriber::fmt::init();

    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    if let Err(e) = rt.block_on(run(cli)) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
