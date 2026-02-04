//! # clawlet CLI
//!
//! Entry point for the `clawlet` binary.
//!
//! Subcommands:
//! - `clawlet init`  — Generate keystore and default policy
//! - `clawlet serve` — Start the RPC server

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
        Commands::Serve { config } => commands::serve::run(config).await,
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
