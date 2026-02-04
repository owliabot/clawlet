//! # clawlet CLI
//!
//! Entry point for the `clawlet` binary.
//!
//! Subcommands:
//! - `clawlet init`  — Generate keystore and default policy
//! - `clawlet serve` — Start the RPC server

fn main() {
    // TODO(M1-9, M1-10): implement CLI argument parsing with clap
    eprintln!("clawlet v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("Usage: clawlet <init|serve>");
    eprintln!();
    eprintln!("This is a stub. Subcommands are not yet implemented.");
    std::process::exit(1);
}
