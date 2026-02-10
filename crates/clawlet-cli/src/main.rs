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
use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod commands;

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

        /// Token expiry duration (default: 1y).
        #[arg(long, default_value = "1y")]
        expires: String,

        /// Data directory (default: ~/.clawlet).
        #[arg(long)]
        data_dir: Option<PathBuf>,

        /// Address to bind the HTTP server (default: 127.0.0.1:9100).
        #[arg(long, short)]
        addr: Option<SocketAddr>,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Init {
            from_mnemonic,
            data_dir,
        } => commands::init::run(from_mnemonic, data_dir),
        Commands::Serve { config, addr } => commands::serve::run(config, addr).await,
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
        } => commands::start::run(agent, scope, expires, data_dir, addr).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
