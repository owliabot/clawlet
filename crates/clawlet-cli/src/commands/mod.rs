//! CLI subcommand implementations.

use std::path::PathBuf;

pub mod auth;
pub mod connect;
pub mod export_mnemonic;
pub mod init;
pub mod send;
pub mod serve;
pub mod start;
pub mod stop;
pub mod transfer;

/// Read a password from the terminal, with fallback to environment variable.
/// Returns an error if neither is available (non-interactive mode without env var).
pub(crate) fn read_password(
    prompt: &str,
    env_var: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::IsTerminal;

    // Try environment variable first (for non-interactive/CI use)
    if let Ok(pw) = std::env::var(env_var) {
        if !pw.is_empty() {
            return Ok(pw);
        }
    }

    // Check if we have a terminal
    if !std::io::stderr().is_terminal() {
        return Err(format!(
            "Password input requires an interactive terminal.\n\
             Either run this command directly (not through a pipe),\n\
             or set {} environment variable.",
            env_var
        )
        .into());
    }

    Ok(rpassword::prompt_password_stderr(prompt)?)
}

/// Read a line from stdin, or return a default if stdin is not a terminal.
pub(crate) fn read_line_or_default(default: &str) -> Result<String, Box<dyn std::error::Error>> {
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() {
        return Ok(default.to_string());
    }

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

pub(crate) fn resolve_data_dir(
    data_dir: Option<PathBuf>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(dir) = data_dir {
        return Ok(dir);
    }

    let home = dirs::home_dir().ok_or("could not determine home directory")?;
    Ok(home.join(".clawlet"))
}
