//! # clawlet CLI
//!
//! Entry point for the `clawlet` binary.
//!
//! Subcommands:
//! - `clawlet init`  — Generate keystore and default policy
//! - `clawlet serve` — Start the RPC server
//! - `clawlet auth`  — Manage session tokens for AI agents

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

    /// Start the RPC server.
    Serve {
        /// Path to config.yaml (default: ~/.clawlet/config.yaml).
        #[arg(long, short)]
        config: Option<PathBuf>,

        /// Path to Unix domain socket for JSON-RPC interface.
        /// If provided, starts a socket server in addition to iceoryx2.
        /// Default when enabled: /run/clawlet/clawlet.sock
        #[arg(long)]
        socket: Option<PathBuf>,
    },

    /// Manage session tokens for AI agents.
    Auth {
        /// Path to config.yaml (default: ~/.clawlet/config.yaml).
        #[arg(long, short)]
        config: Option<PathBuf>,

        #[command(subcommand)]
        command: commands::auth::AuthCommand,
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
        Commands::Serve { config, socket } => commands::serve::run(config, socket).await,
        Commands::Auth { config, command } => commands::auth::run(command, config),
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
