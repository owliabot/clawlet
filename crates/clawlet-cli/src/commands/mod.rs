//! CLI subcommand implementations.

use std::path::PathBuf;

pub mod auth;
pub mod export_mnemonic;
pub mod init;
pub mod send;
pub mod serve;
pub mod sign_message;
pub mod start;
pub mod stop;
pub mod transfer;

pub(crate) fn resolve_data_dir(
    data_dir: Option<PathBuf>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(dir) = data_dir {
        return Ok(dir);
    }

    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".clawlet"))
}
