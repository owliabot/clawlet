//! `clawlet export-mnemonic` — display the BIP-39 mnemonic from the keystore.

use std::path::PathBuf;

use clawlet_signer::keystore::Keystore;

/// Run the `export-mnemonic` subcommand.
pub fn run(data_dir: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = super::resolve_data_dir(data_dir)?;
    let keystore_dir = data_dir.join("keystore");

    let entries = Keystore::list(&keystore_dir)?;
    if entries.is_empty() {
        return Err("no keystore found — run `clawlet init` first".into());
    }

    let keystore_path = &entries[0];

    let password = super::read_password("Enter keystore password: ", "CLAWLET_PASSWORD")?;
    if password.is_empty() {
        return Err("password entry aborted".into());
    }

    let mnemonic = Keystore::unlock(keystore_path, &password)?;

    crate::tui::show_sensitive(
        &[
            "⚠️  Anyone with this mnemonic can access your funds. Never share it.",
            "",
            "Your mnemonic phrase:",
            "",
            &format!("  {mnemonic}"),
        ],
        "Press Enter to clear and return...",
    )?;

    Ok(())
}
